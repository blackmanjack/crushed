package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public final class BusinessLogicAnalyzer implements Analyzer {

    private static final Set<String> STATE_CHANGING = Set.of("PUT", "PATCH", "POST");
    private static final Set<String> SENSITIVE_FIELDS = Set.of(
            "role", "is_admin", "isadmin", "kyc_status", "balance", "member_id", "admin", "permissions");
    private static final Set<String> RACE_CANDIDATE_KEYWORDS = Set.of(
            "claim", "redeem", "transfer", "checkout", "coupon", "vote", "withdraw");

    @Override
    public String name() {
        return "BusinessLogicAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        if (STATE_CHANGING.contains(context.method())) {
            String responseBody = context.responseBody() == null ? "" : context.responseBody().toLowerCase();
            for (String field : SENSITIVE_FIELDS) {
                if (responseBody.contains("\"" + field + "\"")) {
                    int offset = responseBody.indexOf("\"" + field + "\"");
                    Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, offset,
                            "response contains sensitive field \"" + field + "\"", field);
                    signals.add(new Signal(
                            IssueType.MASS_ASSIGNMENT,
                            endpointKey,
                            Confidence.TENTATIVE,
                            "State-changing request to a profile/user-like endpoint returns sensitive field '" + field +
                                    "'; verify whether this field can also be set by the client (mass assignment).",
                            evidence
                    ));
                }
            }

            String path = context.path() == null ? "" : context.path().toLowerCase();
            for (String keyword : RACE_CANDIDATE_KEYWORDS) {
                if (path.contains(keyword)) {
                    Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, path.indexOf(keyword),
                            "path contains race-condition-prone keyword '" + keyword + "'", null);
                    signals.add(new Signal(
                            IssueType.RACE_CONDITION_CANDIDATE,
                            endpointKey,
                            Confidence.TENTATIVE,
                            "Endpoint performs a state-changing operation ('" + keyword + "') that is a classic " +
                                    "race-condition candidate; validate manually with concurrent requests (Turbo Intruder/Repeater).",
                            evidence
                    ));
                    break;
                }
            }
        }
        return signals;
    }
}
