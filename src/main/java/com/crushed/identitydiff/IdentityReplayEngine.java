package com.crushed.identitydiff;

import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.IssueType;
import com.crushed.model.OwaspRef;
import com.crushed.model.Severity;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Autorize-style replay: re-issues an authenticated request with an alternate identity's
 * credentials and diffs the response against the original. A SAME_ACCESS verdict is a proven
 * BOLA/IDOR/privilege-escalation finding (Status=CONFIRMED), not a passive guess.
 *
 * Only invoked when the "Identity Diff" toggle is ON and the endpoint's host is in scope —
 * callers are responsible for those gates; this class does no scope/toggle checking itself.
 */
public final class IdentityReplayEngine {

    private final RequestSender sender;
    private final ResponseDiffer differ;
    private final ActivityLog activityLog;

    public IdentityReplayEngine(RequestSender sender, ResponseDiffer differ, ActivityLog activityLog) {
        this.sender = sender;
        this.differ = differ;
        this.activityLog = activityLog;
    }

    public List<Finding> replayWithIdentity(ReplayableRequest original, ReplayResult originalResult, Identity identity) {
        ReplayableRequest substituted = substituteIdentity(original, identity);
        ReplayResult replayResult;
        try {
            replayResult = sender.send(substituted);
        } catch (Exception e) {
            activityLog.error("IdentityReplayEngine", original.originalHistoryId(),
                    "Replay with identity '" + identity.label() + "' failed: " + e);
            return List.of();
        }

        if (replayResult.networkError()) {
            activityLog.error("IdentityReplayEngine", original.originalHistoryId(),
                    "Replay with identity '" + identity.label() + "' network error: " + replayResult.errorMessage());
            return List.of();
        }

        ResponseDiffer.DiffVerdict verdict = differ.compare(originalResult, replayResult);
        if (verdict != ResponseDiffer.DiffVerdict.SAME_ACCESS) {
            return List.of();
        }

        String endpointKey = original.host() + " " + original.method() + " " + original.path();
        String dedupeKey = "IDENTITY_DIFF|" + endpointKey + "|" + identity.label();

        Evidence originalEvidence = Evidence.of(original.originalHistoryId(), Evidence.Source.RESPONSE, 0,
                "original response status=" + originalResult.statusCode(), null);
        Evidence replayEvidence = Evidence.of(original.originalHistoryId(), Evidence.Source.RESPONSE, 0,
                "replay as '" + identity.label() + "' status=" + replayResult.statusCode() + " (equivalent access)", null);

        Finding finding = new Finding(
                dedupeKey,
                IssueType.IDOR_BOLA,
                endpointKey,
                Severity.HIGH,
                Confidence.CERTAIN,
                Status.CONFIRMED,
                OwaspRef.IDOR_BOLA,
                "Replaying this request with identity '" + identity.label() + "' returned a response " +
                        "indistinguishable from the original owner's — object-level authorization is not enforced.",
                "Enforce object-level authorization checks server-side for every request, independent of client-supplied identifiers.",
                List.of(originalEvidence, replayEvidence)
        );
        activityLog.bypassed("IdentityReplayEngine", original.originalHistoryId(),
                "Confirmed BOLA/IDOR via identity '" + identity.label() + "' on " + endpointKey);
        return List.of(finding);
    }

    private ReplayableRequest substituteIdentity(ReplayableRequest original, Identity identity) {
        Map<String, String> headers = new HashMap<>(original.headers());
        if (identity.hasBearer()) {
            headers.put("Authorization", identity.authorizationHeaderValue());
            headers.remove("Cookie");
        } else if (identity.hasCookie()) {
            headers.put("Cookie", identity.cookieHeaderValue());
            headers.remove("Authorization");
        }
        return new ReplayableRequest(original.originalHistoryId(), original.host(), original.method(),
                original.path(), headers, original.body());
    }
}
