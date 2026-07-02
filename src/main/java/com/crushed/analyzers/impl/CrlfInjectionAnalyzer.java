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
import java.util.Map;

/**
 * Passive CRLF-injection candidate heuristic: a request parameter's value is reflected into a
 * response HEADER (Location/Set-Cookie/etc) rather than the body. This is a narrow, low-noise
 * heuristic — actual CRLF injection requires active confirmation (see CrlfInjectionDetector).
 */
public final class CrlfInjectionAnalyzer implements Analyzer {

    private static final List<String> HEADER_SINKS = List.of("Location", "Set-Cookie", "Cache-Control", "Refresh");

    @Override
    public String name() {
        return "CrlfInjectionAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.requestParamNames() == null || context.requestParamNames().isEmpty()) return List.of();
        Map<String, String> responseHeaders = context.responseHeaders();
        if (responseHeaders == null || responseHeaders.isEmpty()) return List.of();

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        String requestRaw = context.requestRaw() == null ? "" : context.requestRaw();

        for (String param : context.requestParamNames()) {
            int valueStart = findParamValue(requestRaw, param);
            if (valueStart < 0) continue;
            String value = extractValue(requestRaw, valueStart);
            if (value.length() < 3) continue;

            for (String headerName : HEADER_SINKS) {
                String headerValue = responseHeaders.get(headerName);
                if (headerValue == null || !headerValue.contains(value)) continue;

                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                        headerName + ": " + headerValue, param);
                signals.add(new Signal(IssueType.CRLF_INJECTION, endpointKey, Confidence.TENTATIVE,
                        "Parameter '" + param + "' is reflected into the '" + headerName + "' response header — " +
                                "candidate CRLF injection / HTTP response splitting sink.", evidence));
            }
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
