package com.crushed.analyzers;

import com.crushed.analyzers.impl.SecurityHeaderAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SecurityHeaderAnalyzerTest {

    private final SecurityHeaderAnalyzer analyzer = new SecurityHeaderAnalyzer();

    @Test
    void flagsAllMissingHeadersOnBareHtmlResponse() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/", 200,
                Map.of(), Map.of(), List.of(), "", "<html></html>", "text/html", true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.MISSING_HSTS));
        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.MISSING_X_CONTENT_TYPE_OPTIONS));
        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.MISSING_CLICKJACKING_PROTECTION));
        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.MISSING_CSP));
    }

    @Test
    void doesNotFlagHstsMissingOverPlainHttp() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/", 200,
                Map.of(), Map.of(), List.of(), "", "<html></html>", "text/html", false);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().noneMatch(s -> s.issueType() == IssueType.MISSING_HSTS));
    }

    @Test
    void flagsServerHeaderDisclosure() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/", 200,
                Map.of(), Map.of("Server", "nginx/1.18.0"), List.of(), "", "<html></html>", "text/html", true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.TECH_STACK_DISCLOSURE));
    }

    @Test
    void noFindingsWhenAllHeadersPresent() {
        Map<String, String> headers = Map.of(
                "Strict-Transport-Security", "max-age=31536000",
                "X-Content-Type-Options", "nosniff",
                "X-Frame-Options", "DENY",
                "Content-Security-Policy", "default-src 'self'");
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/", 200,
                Map.of(), headers, List.of(), "", "<html></html>", "text/html", true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    @Test
    void ignoresNonHtmlResponses() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/app.js", 200,
                Map.of(), Map.of(), List.of(), "", "console.log(1)", "application/javascript", true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
