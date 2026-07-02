package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.*;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.function.Function;

/**
 * Active boolean-based SQLi confirmation: send a "true" condition and a "false" condition
 * variant of the same payload; a differing response (length/status) between the two proves
 * the input reaches a SQL query, independent of any error message being visible.
 */
public final class SqliDetector {

    private static final String TRUE_PAYLOAD = "' AND '1'='1";
    private static final String FALSE_PAYLOAD = "' AND '1'='2";

    private final WafBypassEngine bypassEngine;
    private final ActivityLog activityLog;

    public SqliDetector(WafBypassEngine bypassEngine, ActivityLog activityLog) {
        this.bypassEngine = bypassEngine;
        this.activityLog = activityLog;
    }

    public List<Finding> probe(int historyId, String endpointKey, String paramName, Function<String, ReplayResult> sender) {
        WafBypassEngine.Outcome trueOutcome = bypassEngine.sendWithAutoBypass(
                historyId, "SqliDetector", TRUE_PAYLOAD, sender, r -> !r.networkError());
        if (!trueOutcome.confirmed()) {
            return List.of();
        }
        ReplayResult falseResult = sender.apply(FALSE_PAYLOAD);

        boolean differs = trueOutcome.finalResult().statusCode() != falseResult.statusCode()
                || Math.abs(trueOutcome.finalResult().body().length() - falseResult.body().length()) > 5;

        if (!differs) {
            return List.of();
        }

        Evidence trueEvidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                "TRUE condition (" + trueOutcome.techniqueUsed() + "): status=" + trueOutcome.finalResult().statusCode()
                        + " len=" + trueOutcome.finalResult().body().length(), paramName);
        Evidence falseEvidence = Evidence.of(historyId, Evidence.Source.RESPONSE, 0,
                "FALSE condition: status=" + falseResult.statusCode() + " len=" + falseResult.body().length(), paramName);

        Finding finding = new Finding(
                "SQLI|" + endpointKey + "|" + paramName,
                IssueType.SQL_INJECTION,
                endpointKey,
                Severity.HIGH,
                Confidence.CERTAIN,
                Status.CONFIRMED,
                OwaspRef.SQLI,
                "Boolean-based blind SQL injection confirmed: TRUE and FALSE conditions on parameter '"
                        + paramName + "' produce measurably different responses.",
                com.crushed.core.RemediationCatalog.forIssueType(IssueType.SQL_INJECTION),
                List.of(trueEvidence, falseEvidence)
        );
        activityLog.bypassed("SqliDetector", historyId, "Confirmed boolean-based SQLi on " + endpointKey);
        return List.of(finding);
    }
}
