package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;

/** Passive GraphQL awareness: detect endpoint + introspection enabled. */
public final class GraphQlAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "GraphQlAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String body = context.requestBody();
        if (body == null || !("POST".equalsIgnoreCase(context.method()))) return List.of();
        boolean looksLikeGraphQl = body.contains("\"query\"") || body.contains("\"operationName\"") || body.contains("mutation ") || body.contains("query ");
        if (!looksLikeGraphQl) return List.of();

        String responseBody = context.responseBody() == null ? "" : context.responseBody();
        boolean introspectionEnabled = responseBody.contains("__schema") || responseBody.contains("__type") || body.contains("__schema");

        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        if (!introspectionEnabled) return List.of();

        Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                "response body contains __schema/__type", "query");
        return List.of(new Signal(
                IssueType.GRAPHQL_INTROSPECTION,
                endpointKey,
                Confidence.FIRM,
                "GraphQL introspection appears enabled, exposing the full schema to any caller.",
                evidence
        ));
    }
}
