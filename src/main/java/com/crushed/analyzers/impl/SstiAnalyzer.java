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

public final class SstiAnalyzer implements Analyzer {

    private static final Set<String> TEMPLATE_ISH_PARAMS = Set.of("template", "content", "name", "message", "body");

    @Override
    public String name() {
        return "SstiAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.requestParamNames() == null) return List.of();
        String mime = context.responseMimeType() == null ? "" : context.responseMimeType().toLowerCase();
        if (!mime.contains("html")) return List.of();

        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        for (String param : context.requestParamNames()) {
            if (TEMPLATE_ISH_PARAMS.contains(param.toLowerCase())) {
                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                        "parameter '" + param + "' may be rendered into a server-side template", param);
                return List.of(new Signal(IssueType.SSTI, endpointKey, Confidence.TENTATIVE,
                        "Parameter '" + param + "' feeds a server-rendered page (template/notification-like field) — " +
                                "candidate for server-side template injection.",
                        evidence));
            }
        }
        return List.of();
    }
}
