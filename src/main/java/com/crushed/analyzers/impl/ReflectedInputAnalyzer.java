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

/**
 * Passive generic-reflection heuristic: request param value echoed verbatim anywhere in the
 * response body, regardless of content-type. Lower-confidence and content-type-agnostic sibling
 * of XssAnalyzer (which requires HTML + special chars) — a support signal for chaining, not a
 * standalone vuln claim.
 */
public final class ReflectedInputAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "ReflectedInputAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String responseBody = context.responseBody();
        if (responseBody == null || responseBody.isEmpty()) return List.of();
        if (context.requestParamNames() == null || context.requestParamNames().isEmpty()) return List.of();

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        String requestRaw = context.requestRaw() == null ? "" : context.requestRaw();

        for (String param : context.requestParamNames()) {
            int valueStart = findParamValue(requestRaw, param);
            if (valueStart < 0) continue;
            String value = extractValue(requestRaw, valueStart);
            if (value.length() < 6) continue;

            int reflectedAt = responseBody.indexOf(value);
            if (reflectedAt < 0) continue;

            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, reflectedAt,
                    responseBody.substring(Math.max(0, reflectedAt - 40), Math.min(responseBody.length(), reflectedAt + 40)),
                    param);
            signals.add(new Signal(IssueType.REFLECTED_INPUT, endpointKey, Confidence.TENTATIVE,
                    "Parameter '" + param + "' value is reflected verbatim in the response body — candidate " +
                            "input point for injection/cache-poisoning/log-injection chains.", evidence));
        }
        return signals;
    }

    private int findParamValue(String requestRaw, String param) {
        int idx = requestRaw.indexOf(param + "=");
        return idx < 0 ? -1 : idx + param.length() + 1;
    }

    private String extractValue(String requestRaw, int start) {
        int end = start;
        while (end < requestRaw.length() && "&\r\n ".indexOf(requestRaw.charAt(end)) < 0) end++;
        return requestRaw.substring(start, end);
    }
}
