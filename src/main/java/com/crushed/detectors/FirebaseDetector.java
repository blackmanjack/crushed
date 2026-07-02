package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.ui.ActivityLog;

import java.util.List;

/**
 * Pure decision logic: an unauthenticated Firestore REST query returning HTTP 200 with a
 * response body means the project's security rules are left at "allow read, write" (or
 * similarly permissive) — a properly secured project returns 403. Network I/O is handled by
 * FirebaseSender in core/.
 */
public final class FirebaseDetector {

    private final ActivityLog activityLog;

    public FirebaseDetector(ActivityLog activityLog) {
        this.activityLog = activityLog;
    }

    public List<Finding> confirm(int historyId, String endpointKey, String projectId, ReplayResult firestoreResult) {
        if (firestoreResult.networkError()) {
            activityLog.error("FirebaseDetector", historyId, "Firestore probe failed: " + firestoreResult.errorMessage());
            return List.of();
        }
        if (firestoreResult.statusCode() != 200) {
            activityLog.info("FirebaseDetector", historyId,
                    "Firestore REST query for project '" + projectId + "' returned " + firestoreResult.statusCode()
                            + " — security rules appear to require authentication.");
            return List.of();
        }

        Evidence evidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                "Unauthenticated GET to Firestore REST API for project '" + projectId + "' returned HTTP 200: "
                        + truncate(firestoreResult.body()), null);

        Finding finding = new Finding(
                "FIREBASE_CONFIRMED|" + endpointKey + "|" + projectId,
                IssueType.FIREBASE_MISCONFIGURATION,
                endpointKey,
                Severity.HIGH,
                Confidence.CERTAIN,
                Status.CONFIRMED,
                OwaspRef.FIREBASE_MISCONFIG,
                "An unauthenticated Firestore REST query for project '" + projectId + "' returned HTTP 200 with " +
                        "data — the project's security rules are left at a default allow-all state, exposing " +
                        "collections to anyone without credentials.",
                "Set Firestore/Storage/RTDB security rules to require request.auth != null and scope reads/writes " +
                        "to the owning user.",
                List.of(evidence)
        );
        activityLog.bypassed("FirebaseDetector", historyId, "Confirmed Firebase misconfiguration for project '" + projectId + "'");
        return List.of(finding);
    }

    private String truncate(String body) {
        if (body == null) return "";
        return body.length() > 200 ? body.substring(0, 200) + "..." : body;
    }
}
