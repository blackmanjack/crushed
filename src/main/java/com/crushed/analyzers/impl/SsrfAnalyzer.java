package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;
import java.util.Set;

public final class SsrfAnalyzer implements Analyzer {

    private static final Set<String> SSRF_PARAM_HINTS = Set.of(
            "url", "uri", "callback", "webhook", "target", "dest", "proxy", "fetch", "image", "avatar", "path", "src");

    @Override
    public String name() {
        return "SsrfAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.requestParamNames() == null) return List.of();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        for (String param : context.requestParamNames()) {
            if (SSRF_PARAM_HINTS.contains(param.toLowerCase())) {
                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                        "parameter name suggests server-side fetch-by-URL: " + param, param);
                return List.of(new Signal(IssueType.SSRF, endpointKey, Confidence.TENTATIVE,
                        "Parameter '" + param + "' suggests the server fetches a resource server-side using a " +
                                "client-supplied URL/host — candidate for SSRF.",
                        evidence));
            }
        }
        return List.of();
    }
}
