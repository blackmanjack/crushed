package com.crushed.core;

import com.crushed.detectors.CrlfInjectionDetector;
import com.crushed.detectors.FirebaseDetector;
import com.crushed.detectors.FirebaseProjectIdExtractor;
import com.crushed.detectors.MassAssignmentDetector;
import com.crushed.detectors.OastConfirmedDetector;
import com.crushed.detectors.PathTraversalDetector;
import com.crushed.detectors.SqliDetector;
import com.crushed.detectors.XssDetector;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.IssueType;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Routes a Finding to the right active detector by IssueType, using the finding's own Evidence
 * (Req #id + param name) to rebuild the request. SQLi/XSS confirm synchronously; SSRF/XXE/RCE
 * confirm asynchronously via an OAST callback (registered here, resolved later by
 * OastCorrelator). XXE/RCE substitute the whole request body (a single named parameter isn't
 * the right unit for a DOCTYPE payload or a command-injection field); SQLi/XSS/SSRF substitute
 * one named parameter. Issue types without a wired confirmation path (Mass Assignment, Firebase,
 * DOM-XSS-chain, AI-session, IDOR beyond identity-diff) are reported to the ActivityLog rather
 * than silently doing nothing.
 */
public final class ActiveConfirmationService {

    private final RequestStore requestStore;
    private final ParameterSubstitutingSender paramSenderFactory;
    private final BodySubstitutingSender bodySenderFactory;
    private final MassAssignmentSender massAssignmentSenderFactory;
    private final FirebaseSender firebaseSenderFactory;
    private final SqliDetector sqliDetector;
    private final XssDetector xssDetector;
    private final OastConfirmedDetector oastConfirmedDetector;
    private final MassAssignmentDetector massAssignmentDetector;
    private final FirebaseDetector firebaseDetector;
    private final PathTraversalDetector pathTraversalDetector;
    private final CrlfInjectionDetector crlfInjectionDetector;
    private final FirebaseProjectIdExtractor firebaseProjectIdExtractor = new FirebaseProjectIdExtractor();
    private final ActivityLog activityLog;

    public ActiveConfirmationService(RequestStore requestStore, ParameterSubstitutingSender paramSenderFactory,
                                      BodySubstitutingSender bodySenderFactory, MassAssignmentSender massAssignmentSenderFactory,
                                      FirebaseSender firebaseSenderFactory, SqliDetector sqliDetector, XssDetector xssDetector,
                                      OastConfirmedDetector oastConfirmedDetector, MassAssignmentDetector massAssignmentDetector,
                                      FirebaseDetector firebaseDetector, PathTraversalDetector pathTraversalDetector,
                                      CrlfInjectionDetector crlfInjectionDetector, ActivityLog activityLog) {
        this.requestStore = requestStore;
        this.paramSenderFactory = paramSenderFactory;
        this.bodySenderFactory = bodySenderFactory;
        this.massAssignmentSenderFactory = massAssignmentSenderFactory;
        this.firebaseSenderFactory = firebaseSenderFactory;
        this.sqliDetector = sqliDetector;
        this.xssDetector = xssDetector;
        this.oastConfirmedDetector = oastConfirmedDetector;
        this.massAssignmentDetector = massAssignmentDetector;
        this.firebaseDetector = firebaseDetector;
        this.pathTraversalDetector = pathTraversalDetector;
        this.crlfInjectionDetector = crlfInjectionDetector;
        this.activityLog = activityLog;
    }

    public List<Finding> confirm(Finding finding) {
        if (finding.evidence().isEmpty()) {
            activityLog.error("ActiveConfirmationService", -1, "Finding has no evidence to confirm against.");
            return List.of();
        }
        int historyId = finding.evidence().get(0).historyId();
        RequestStore.Stored stored = requestStore.get(historyId);
        if (stored == null) {
            activityLog.error("ActiveConfirmationService", historyId, "No stored original request for Req #" + historyId + ".");
            return List.of();
        }

        // Firebase targets a fixed Google-owned host, not the app's own — no named parameter required.
        if (finding.issueType() == IssueType.FIREBASE_MISCONFIGURATION) {
            String responseBody = stored.response() != null ? stored.response().bodyToString() : null;
            String path = stored.request() != null ? stored.request().path() : null;
            Optional<String> projectId = firebaseProjectIdExtractor.extract(responseBody, path);
            if (projectId.isEmpty()) {
                activityLog.info("ActiveConfirmationService", historyId,
                        "Could not extract a Firebase projectId from this finding's traffic; cannot build the probe.");
                return List.of();
            }
            var firestoreResult = firebaseSenderFactory.probeFirestore(projectId.get());
            return firebaseDetector.confirm(historyId, finding.endpointKey(), projectId.get(), firestoreResult);
        }

        // XXE/RCE substitute the whole body — no named parameter required.
        if (finding.issueType() == IssueType.XXE || finding.issueType() == IssueType.RCE) {
            String technique = finding.issueType() == IssueType.XXE ? "DOCTYPE/entity body substitution" : "command-injection body substitution";
            String payloadTemplate = finding.issueType() == IssueType.XXE
                    ? OastConfirmedDetector.xxeBlindPayload()
                    : OastConfirmedDetector.rceOobPayload();
            oastConfirmedDetector.probeAsync(historyId, finding.endpointKey(), finding.issueType(), technique,
                    payloadTemplate, bodySenderFactory.forBody(stored));
            activityLog.info("ActiveConfirmationService", historyId,
                    finding.issueType() + " probe planted; result (if any) will appear once an OAST callback arrives.");
            return List.of();
        }

        String paramName = finding.evidence().stream()
                .map(Evidence::paramOrFieldName)
                .filter(java.util.Objects::nonNull)
                .findFirst()
                .orElse(null);
        if (paramName == null) {
            activityLog.info("ActiveConfirmationService", historyId,
                    "No parameter associated with this finding; cannot build a substitution-based active probe.");
            return List.of();
        }

        return switch (finding.issueType()) {
            case SQL_INJECTION -> sqliDetector.probe(historyId, finding.endpointKey(), paramName,
                    paramSenderFactory.forParameter(stored, paramName));
            case REFLECTED_XSS, DOM_XSS -> xssDetector.probe(historyId, finding.endpointKey(), paramName,
                    paramSenderFactory.forParameter(stored, paramName));
            case PATH_TRAVERSAL -> pathTraversalDetector.probe(historyId, finding.endpointKey(), paramName,
                    paramSenderFactory.forParameter(stored, paramName));
            case CRLF_INJECTION -> crlfInjectionDetector.probe(historyId, finding.endpointKey(), paramName,
                    paramSenderFactory.forParameter(stored, paramName));
            case MASS_ASSIGNMENT -> {
                String marker = "crushed-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
                MassAssignmentSender.ProbeResult probeResult = massAssignmentSenderFactory.probe(stored, paramName, marker);
                yield massAssignmentDetector.confirm(historyId, finding.endpointKey(), paramName, marker,
                        probeResult.writeResponse(), probeResult.readResponse());
            }
            case SSRF -> {
                oastConfirmedDetector.probeAsync(historyId, finding.endpointKey(), IssueType.SSRF,
                        "url-like parameter '" + paramName + "'", OastConfirmedDetector.ssrfPayload(),
                        paramSenderFactory.forParameter(stored, paramName));
                activityLog.info("ActiveConfirmationService", historyId,
                        "SSRF probe planted; result (if any) will appear once an OAST callback arrives.");
                yield List.of();
            }
            default -> {
                activityLog.info("ActiveConfirmationService", historyId,
                        "No active confirmation is wired yet for issue type " + finding.issueType() + ".");
                yield List.of();
            }
        };
    }
}
