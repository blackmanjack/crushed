package com.crushed.analyzers;

import com.crushed.analyzers.impl.ForbiddenResponseAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ForbiddenResponseAnalyzerTest {

    private final ForbiddenResponseAnalyzer analyzer = new ForbiddenResponseAnalyzer();

    @Test
    void flags403Response() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/admin", 403,
                Map.of(), Map.of(), List.of(), "", "Forbidden", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.FORBIDDEN_BYPASS));
    }

    @Test
    void ignores200Response() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/admin", 200,
                Map.of(), Map.of(), List.of(), "", "ok", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
