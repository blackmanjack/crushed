package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;

/** Generalized XXE surface detection (complements ContextAnalyzer's Firebase/office-upload check). */
public final class XxeAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "XxeAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String contentType = context.requestHeaders() == null ? "" : context.requestHeaders().getOrDefault("Content-Type", "");
        String body = context.requestBody() == null ? "" : context.requestBody();
        boolean hasDoctype = body.contains("<!DOCTYPE");

        if (contentType.toLowerCase().contains("xml") && hasDoctype) {
            String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, body.indexOf("<!DOCTYPE"),
                    "request body declares a DOCTYPE inside an XML content-type", null);
            return List.of(new Signal(IssueType.XXE, endpointKey, Confidence.TENTATIVE,
                    "Request declares a DOCTYPE within XML content — if the server's parser resolves external " +
                            "entities, this is exploitable for XXE.",
                    evidence));
        }
        return List.of();
    }
}
