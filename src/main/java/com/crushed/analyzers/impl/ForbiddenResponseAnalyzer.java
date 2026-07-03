package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;

/**
 * Passive candidate signal for any 401/403 response — a low-confidence hint that exists purely
 * so "Confirm Actively" (ForbiddenBypassDetector) has a Finding to hang off of, matching the
 * pattern every other active-confirmable class already uses in this codebase.
 */
public final class ForbiddenResponseAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "ForbiddenResponseAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.responseStatusCode() != 401 && context.responseStatusCode() != 403) return List.of();

        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                "status=" + context.responseStatusCode(), null);

        return List.of(new Signal(IssueType.FORBIDDEN_BYPASS, endpointKey, Confidence.TENTATIVE,
                "Endpoint returned " + context.responseStatusCode() + " — candidate for path-manipulation/" +
                        "header-spoofing access-control bypass techniques.", evidence));
    }
}
