package com.crushed.analyzers;

import com.crushed.analyzers.impl.ReflectedInputAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ReflectedInputAnalyzerTest {

    private final ReflectedInputAnalyzer analyzer = new ReflectedInputAnalyzer();

    @Test
    void flagsVerbatimReflectionInJsonBody() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/search", 200,
                Map.of(), Map.of(), List.of("q"), "q=helloworld123", "{\"echo\":\"helloworld123\"}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.REFLECTED_INPUT));
    }

    @Test
    void ignoresShortValues() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/search", 200,
                Map.of(), Map.of(), List.of("q"), "q=hi", "{\"echo\":\"hi\"}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
