package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;
import java.util.Map;

/**
 * Passive HTTP request-smuggling candidate heuristic: flags a request that sends both
 * Content-Length and Transfer-Encoding headers, or a Transfer-Encoding value that isn't exactly
 * "chunked" (a common obfuscation trick, e.g. "chunked, identity" or extra whitespace/casing) —
 * the same early-warning signal real smuggling scanners (HTTP Request Smuggler) lead with.
 * Passive-only: full confirmation needs raw low-level socket/timing control that Montoya's
 * sendRequest abstraction doesn't expose.
 */
public final class RequestSmugglingAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "RequestSmugglingAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        Map<String, String> headers = context.requestHeaders();
        if (headers == null || headers.isEmpty()) return List.of();

        String contentLength = null;
        String transferEncoding = null;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String key = e.getKey().toLowerCase();
            if (key.equals("content-length")) contentLength = e.getValue();
            if (key.equals("transfer-encoding")) transferEncoding = e.getValue();
        }
        if (transferEncoding == null) return List.of();

        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        boolean hasBoth = contentLength != null;
        boolean obfuscatedTe = !transferEncoding.trim().equalsIgnoreCase("chunked");

        if (!hasBoth && !obfuscatedTe) return List.of();

        String reason = hasBoth
                ? "request sends both Content-Length (" + contentLength + ") and Transfer-Encoding (" + transferEncoding + ")"
                : "Transfer-Encoding value is obfuscated: '" + transferEncoding + "' (not exactly 'chunked')";

        Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0, reason, "Transfer-Encoding");
        return List.of(new Signal(IssueType.REQUEST_SMUGGLING_CANDIDATE, endpointKey, Confidence.TENTATIVE,
                "Candidate HTTP request smuggling: " + reason + " — front-end/back-end servers may disagree on " +
                        "request framing.", evidence));
    }
}
