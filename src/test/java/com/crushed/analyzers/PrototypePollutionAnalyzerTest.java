package com.crushed.analyzers;

import com.crushed.analyzers.impl.PrototypePollutionAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PrototypePollutionAnalyzerTest {

    private final PrototypePollutionAnalyzer analyzer = new PrototypePollutionAnalyzer();

    @Test
    void flagsProtoKeyInJsonBody() {
        String body = "{\"__proto__\":{\"isAdmin\":true}}";
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/api/merge", 200,
                Map.of("Content-Type", "application/json"), Map.of(), List.of(), body, "", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.PROTOTYPE_POLLUTION));
    }

    @Test
    void ignoresBenignJsonBody() {
        String body = "{\"name\":\"alice\"}";
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/api/merge", 200,
                Map.of("Content-Type", "application/json"), Map.of(), List.of(), body, "", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
