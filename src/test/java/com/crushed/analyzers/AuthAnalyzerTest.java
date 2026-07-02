package com.crushed.analyzers;

import com.crushed.analyzers.impl.AuthAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AuthAnalyzerTest {

    private final AuthAnalyzer analyzer = new AuthAnalyzer();

    @Test
    void flagsSequentialIdInPath() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "GET", "/api/v1/users/1002/profile", 200,
                Map.of(), Map.of(), List.of(), "", "{}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.IDOR_BOLA));
    }

    @Test
    void ignoresNonNumericPath() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "GET", "/api/v1/users/me/profile", 200,
                Map.of(), Map.of(), List.of(), "", "{}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
