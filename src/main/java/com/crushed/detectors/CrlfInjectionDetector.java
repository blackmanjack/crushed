package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/**
 * Active CRLF-injection confirmation: inject a CRLF sequence followed by a marker header into a
 * parameter, then check whether the marker header literally appears in the raw response headers
 * (proving the payload split into a new header rather than being encoded/stripped).
 */
public final class CrlfInjectionDetector {

    private final ActivityLog activityLog;

    public CrlfInjectionDetector(ActivityLog activityLog) {
        this.activityLog = activityLog;
    }

    public List<Finding> probe(int historyId, String endpointKey, String paramName, Function<String, ReplayResult> sender) {
        String marker = "crushed-crlf-" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String markerHeader = "X-Crushed-Crlf";
        String payload = "%0d%0a" + markerHeader + ": " + marker;

        ReplayResult result;
        try {
            result = sender.apply(payload);
        } catch (Exception e) {
            activityLog.error("CrlfInjectionDetector", historyId, "Send failed: " + e);
            return List.of();
        }
        if (result.networkError()) {
            return List.of();
        }

        boolean injected = result.headers().entrySet().stream()
                .anyMatch(h -> h.getKey().equalsIgnoreCase(markerHeader) && h.getValue().contains(marker));
        if (!injected) {
            return List.of();
        }

        Evidence evidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                "injected header " + markerHeader + ": " + marker + " observed in raw response headers", paramName);

        Finding finding = new Finding(
                "CRLF_INJECTION|" + endpointKey + "|" + paramName,
                IssueType.CRLF_INJECTION,
                endpointKey,
                Severity.MEDIUM,
                Confidence.CERTAIN,
                Status.CONFIRMED,
                OwaspRef.CRLF_INJECTION,
                "CRLF injection confirmed: parameter '" + paramName + "' allows injecting a new response header " +
                        "(" + markerHeader + ") via CR/LF characters.",
                com.crushed.core.RemediationCatalog.forIssueType(IssueType.CRLF_INJECTION),
                List.of(evidence)
        );
        activityLog.bypassed("CrlfInjectionDetector", historyId, "Confirmed CRLF injection on " + endpointKey);
        return List.of(finding);
    }
}
