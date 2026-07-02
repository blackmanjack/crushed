package com.crushed.analyzers;

import com.crushed.analyzers.impl.OAuthAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class OAuthAnalyzerTest {

    private final OAuthAnalyzer analyzer = new OAuthAnalyzer();

    @Test
    void flagsMissingState() {
        AnalysisContext ctx = TestFixtures.http("idp.example.com", "GET", "/oauth/authorize", 200,
                Map.of(), Map.of(), List.of("response_type", "client_id", "redirect_uri"),
                "response_type=code&client_id=abc&redirect_uri=https://app.example.com/cb", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.OAUTH_MISCONFIGURATION));
    }

    @Test
    void flagsImplicitFlow() {
        AnalysisContext ctx = TestFixtures.http("idp.example.com", "GET", "/oauth/authorize", 200,
                Map.of(), Map.of(), List.of("response_type", "client_id", "state"),
                "response_type=token&client_id=abc&state=xyz", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.OAUTH_MISCONFIGURATION));
    }

    @Test
    void flagsMissingPkce() {
        AnalysisContext ctx = TestFixtures.http("idp.example.com", "GET", "/oauth/authorize", 200,
                Map.of(), Map.of(), List.of("response_type", "client_id", "state"),
                "response_type=code&client_id=abc&state=xyz", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.OAUTH_MISCONFIGURATION));
    }

    @Test
    void noSignalWhenWellFormed() {
        AnalysisContext ctx = TestFixtures.http("idp.example.com", "GET", "/oauth/authorize", 200,
                Map.of(), Map.of(), List.of("response_type", "client_id", "state", "code_challenge"),
                "response_type=code&client_id=abc&state=xyz&code_challenge=abc123", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    @Test
    void ignoresNonAuthRequests() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/dashboard", 200,
                Map.of(), Map.of(), List.of("tab"), "tab=home", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
