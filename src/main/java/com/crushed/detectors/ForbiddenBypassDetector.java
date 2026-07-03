package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.function.Function;

/**
 * Active 403/401 access-control-bypass confirmation: retries a stored 401/403 request with a
 * small fixed set of path-manipulation/header-spoofing variants and confirms if any variant
 * returns a non-401/403 status with a materially different (larger) body — proving the
 * restriction can be bypassed.
 */
public final class ForbiddenBypassDetector {

    private static final List<String> VARIANTS = List.of(
            "trailing-dot", "double-slash", "dot-segment", "x-original-url", "x-rewrite-url", "x-forwarded-for");

    private final ActivityLog activityLog;

    public ForbiddenBypassDetector(ActivityLog activityLog) {
        this.activityLog = activityLog;
    }

    public List<Finding> probe(int historyId, String endpointKey, int originalStatus, int originalBodyLength,
                                Function<String, ReplayResult> sender) {
        for (String variant : VARIANTS) {
            ReplayResult result;
            try {
                result = sender.apply(variant);
            } catch (Exception e) {
                activityLog.error("ForbiddenBypassDetector", historyId, "Send failed for variant=" + variant + ": " + e);
                continue;
            }
            if (result.networkError()) continue;

            boolean bypassed = result.statusCode() != 401 && result.statusCode() != 403
                    && result.statusCode() != originalStatus
                    && result.body().length() > originalBodyLength + 20;
            if (!bypassed) continue;

            Evidence evidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                    "variant=" + variant + " status=" + result.statusCode() + " len=" + result.body().length()
                            + " (original status=" + originalStatus + " len=" + originalBodyLength + ")", null);

            Finding finding = new Finding(
                    "FORBIDDEN_BYPASS|" + endpointKey,
                    IssueType.FORBIDDEN_BYPASS,
                    endpointKey,
                    Severity.HIGH,
                    Confidence.CERTAIN,
                    Status.CONFIRMED,
                    OwaspRef.FORBIDDEN_BYPASS,
                    "403/401 access-control bypass confirmed: variant '" + variant + "' returns a materially " +
                            "different, non-restricted response.",
                    com.crushed.core.RemediationCatalog.forIssueType(IssueType.FORBIDDEN_BYPASS),
                    List.of(evidence)
            );
            activityLog.bypassed("ForbiddenBypassDetector", historyId, "Confirmed 403/401 bypass on " + endpointKey + " via " + variant);
            return List.of(finding);
        }
        return List.of();
    }
}
