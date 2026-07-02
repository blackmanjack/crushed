package com.crushed.analyzers;

import com.crushed.analyzers.impl.CrlfInjectionAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CrlfInjectionAnalyzerTest {

    private final CrlfInjectionAnalyzer analyzer = new CrlfInjectionAnalyzer();

    @Test
    void flagsParamReflectedIntoLocationHeader() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/redirect", 302,
                Map.of(), Map.of("Location", "https://app.example.com/next?target=abc123"),
                List.of("target"), "target=abc123", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.CRLF_INJECTION));
    }

    @Test
    void ignoresWhenNoHeaderReflection() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/redirect", 302,
                Map.of(), Map.of("Location", "https://app.example.com/next"),
                List.of("target"), "target=abc123", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
