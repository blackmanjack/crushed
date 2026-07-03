package com.crushed.analyzers;

import com.crushed.analyzers.impl.CookieSecurityAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CookieSecurityAnalyzerTest {

    private final CookieSecurityAnalyzer analyzer = new CookieSecurityAnalyzer();

    @Test
    void flagsAllThreeMissingAttributesOnHttps() {
        String responseRaw = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n<html></html>";
        AnalysisContext ctx = new AnalysisContext(1, "app.example.com", "GET", "/login", "", responseRaw, 200,
                Map.of(), Map.of(), List.of(), "", "<html></html>", "text/html", false, -1, true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.COOKIE_MISSING_SECURE_FLAG));
        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.COOKIE_MISSING_HTTPONLY_FLAG));
        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.COOKIE_MISSING_SAMESITE));
    }

    @Test
    void doesNotFlagSecureMissingOverPlainHttp() {
        String responseRaw = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\n<html></html>";
        AnalysisContext ctx = new AnalysisContext(1, "app.example.com", "GET", "/login", "", responseRaw, 200,
                Map.of(), Map.of(), List.of(), "", "<html></html>", "text/html", false, -1, false);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().noneMatch(s -> s.issueType() == IssueType.COOKIE_MISSING_SECURE_FLAG));
    }

    @Test
    void noFindingsWhenCookieIsFullyHardened() {
        String responseRaw = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict\r\n\r\n<html></html>";
        AnalysisContext ctx = new AnalysisContext(1, "app.example.com", "GET", "/login", "", responseRaw, 200,
                Map.of(), Map.of(), List.of(), "", "<html></html>", "text/html", false, -1, true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    @Test
    void flagsSameSiteNoneWithoutSecure() {
        String responseRaw = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; SameSite=None\r\n\r\n<html></html>";
        AnalysisContext ctx = new AnalysisContext(1, "app.example.com", "GET", "/login", "", responseRaw, 200,
                Map.of(), Map.of(), List.of(), "", "<html></html>", "text/html", false, -1, true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.COOKIE_MISSING_SAMESITE));
    }

    @Test
    void handlesMultipleSetCookieHeaders() {
        String responseRaw = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\nSet-Cookie: csrf=xyz789; Secure; HttpOnly; SameSite=Strict\r\n\r\n<html></html>";
        AnalysisContext ctx = new AnalysisContext(1, "app.example.com", "GET", "/login", "", responseRaw, 200,
                Map.of(), Map.of(), List.of(), "", "<html></html>", "text/html", false, -1, true);

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> "session".equals(s.evidence().paramOrFieldName())));
        assertTrue(signals.stream().noneMatch(s -> "csrf".equals(s.evidence().paramOrFieldName())));
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
