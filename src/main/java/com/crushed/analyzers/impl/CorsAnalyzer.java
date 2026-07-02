package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;

/** Passive CORS misconfiguration: ACAO reflects Origin (or is null/*) together with credentials allowed. */
public final class CorsAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "CorsAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        var headers = context.responseHeaders();
        if (headers == null) return List.of();

        String acao = headers.get("Access-Control-Allow-Origin");
        String acac = headers.get("Access-Control-Allow-Credentials");
        String requestOrigin = context.requestHeaders() == null ? null : context.requestHeaders().get("Origin");

        if (acao == null) return List.of();

        boolean reflectsOrigin = requestOrigin != null && acao.equals(requestOrigin);
        boolean isNullOrigin = "null".equalsIgnoreCase(acao);
        boolean credentialsAllowed = "true".equalsIgnoreCase(acac);

        if ((reflectsOrigin || isNullOrigin) && credentialsAllowed) {
            String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                    "Access-Control-Allow-Origin: " + acao + " / Access-Control-Allow-Credentials: " + acac,
                    "Access-Control-Allow-Origin");
            return List.of(new Signal(
                    IssueType.CORS_MISCONFIGURATION,
                    endpointKey,
                    Confidence.FIRM,
                    "Response reflects request Origin (or uses 'null') in ACAO while allowing credentials — " +
                            "any origin can read authenticated responses via CORS.",
                    evidence
            ));
        }
        return List.of();
    }
}
