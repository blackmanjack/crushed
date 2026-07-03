package com.crushed.analyzers;

import com.crushed.analyzers.impl.DeserializationAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class DeserializationAnalyzerTest {

    private final DeserializationAnalyzer analyzer = new DeserializationAnalyzer();

    @Test
    void flagsBase64ArmoredPrefix() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/api/session", 200,
                Map.of(), Map.of(), List.of("token"), "token=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA%3D%3D",
                "", "application/x-www-form-urlencoded");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.INSECURE_DESERIALIZATION));
    }

    @Test
    void ignoresBenignBody() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/api/session", 200,
                Map.of(), Map.of(), List.of("token"), "token=hello", "", "application/x-www-form-urlencoded");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
