package com.crushed.analyzers;

import com.crushed.analyzers.impl.CorsAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CorsAnalyzerTest {

    private final CorsAnalyzer analyzer = new CorsAnalyzer();

    @Test
    void flagsReflectedOriginWithCredentials() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "GET", "/api/data", 200,
                Map.of("Origin", "https://evil.example"),
                Map.of("Access-Control-Allow-Origin", "https://evil.example", "Access-Control-Allow-Credentials", "true"),
                List.of(), "", "", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.CORS_MISCONFIGURATION));
    }

    @Test
    void doesNotFlagWildcardWithoutCredentials() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "GET", "/api/data", 200,
                Map.of("Origin", "https://evil.example"),
                Map.of("Access-Control-Allow-Origin", "*"),
                List.of(), "", "", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
