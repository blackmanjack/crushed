package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;

/** Active reflected-XSS confirmation via a unique canary marker, with auto WAF-bypass retry. */
public final class XssDetector {

    private final WafBypassEngine bypassEngine;
    private final ActivityLog activityLog;

    public XssDetector(WafBypassEngine bypassEngine, ActivityLog activityLog) {
        this.bypassEngine = bypassEngine;
        this.activityLog = activityLog;
    }

    public List<Finding> probe(int historyId, String endpointKey, String paramName, Function<String, ReplayResult> sender) {
        String canary = "crushed" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        String purePayload = "<script>" + canary + "</script>";

        WafBypassEngine.Outcome outcome = bypassEngine.sendWithAutoBypass(
                historyId, "XssDetector", purePayload, sender,
                r -> !r.networkError() && r.body() != null && r.body().contains(canary) && r.body().contains("<script"));

        if (!outcome.confirmed()) {
            return List.of();
        }

        Evidence evidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                "Canary '" + canary + "' reflected unencoded (technique=" + outcome.techniqueUsed() + ")", paramName);

        Finding finding = new Finding(
                "XSS|" + endpointKey + "|" + paramName,
                IssueType.REFLECTED_XSS,
                endpointKey,
                Severity.MEDIUM,
                Confidence.CERTAIN,
                Status.CONFIRMED,
                OwaspRef.XSS,
                "Reflected XSS confirmed: a unique canary payload on parameter '" + paramName
                        + "' is reflected unencoded in the HTML response.",
                com.crushed.core.RemediationCatalog.forIssueType(IssueType.REFLECTED_XSS),
                List.of(evidence)
        );
        activityLog.bypassed("XssDetector", historyId, "Confirmed reflected XSS on " + endpointKey);
        return List.of(finding);
    }
}
