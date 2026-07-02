package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.ui.ActivityLog;

import java.util.List;

/**
 * Pure decision logic for mass-assignment confirmation: given the response(s) observed after
 * injecting an extra field into a state-changing (PUT/PATCH) request, decide whether the
 * injected value actually persisted server-side. Network I/O (injecting the field, sending the
 * write, sending a follow-up read) is handled by MassAssignmentSender in core/ — this class
 * only makes the confirm/no-confirm call so the logic is unit-testable without a live MontoyaApi.
 */
public final class MassAssignmentDetector {

    private final ActivityLog activityLog;

    public MassAssignmentDetector(ActivityLog activityLog) {
        this.activityLog = activityLog;
    }

    /**
     * @param writeResponse response to the PUT/PATCH carrying the injected field
     * @param readResponse  response to a follow-up read of the same resource (nullable if unavailable)
     */
    public List<Finding> confirm(int historyId, String endpointKey, String fieldName, String markerValue,
                                  ReplayResult writeResponse, ReplayResult readResponse) {
        boolean persistedInWrite = !writeResponse.networkError() && bodyContainsMarker(writeResponse.body(), fieldName, markerValue);
        boolean persistedInRead = readResponse != null && !readResponse.networkError()
                && bodyContainsMarker(readResponse.body(), fieldName, markerValue);

        if (!persistedInWrite && !persistedInRead) {
            activityLog.info("MassAssignmentDetector", historyId,
                    "Injected field '" + fieldName + "' did not persist — server likely allow-lists updatable fields.");
            return List.of();
        }

        Evidence writeEvidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                "PUT/PATCH response after injecting " + fieldName + "=" + markerValue, fieldName);
        Finding finding = new Finding(
                "MASS_ASSIGNMENT_CONFIRMED|" + endpointKey + "|" + fieldName,
                IssueType.MASS_ASSIGNMENT,
                endpointKey,
                Severity.HIGH,
                Confidence.CERTAIN,
                Status.CONFIRMED,
                OwaspRef.MASS_ASSIGNMENT,
                "Injecting field '" + fieldName + "' into the request body and observing it " +
                        (persistedInRead ? "persist on a follow-up read" : "reflected back in the write response") +
                        " confirms the server accepts client-supplied values for this field without an allow-list.",
                "Use explicit allow-lists for updatable fields; never bind request JSON directly to a persistence model.",
                List.of(writeEvidence)
        );
        activityLog.bypassed("MassAssignmentDetector", historyId, "Confirmed mass assignment via field '" + fieldName + "' on " + endpointKey);
        return List.of(finding);
    }

    private boolean bodyContainsMarker(String body, String fieldName, String markerValue) {
        if (body == null) return false;
        return body.contains(markerValue) && body.contains(fieldName);
    }
}
