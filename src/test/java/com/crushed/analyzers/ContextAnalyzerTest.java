package com.crushed.analyzers;

import com.crushed.analyzers.impl.ContextAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ContextAnalyzerTest {

    private final ContextAnalyzer analyzer = new ContextAnalyzer();

    @Test
    void flagsFirebaseInitJson() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/__/firebase/init.json", 200,
                Map.of(), Map.of(), List.of(), "", "{\"projectId\":\"demo\"}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.FIREBASE_MISCONFIGURATION));
    }

    @Test
    void flagsXlsxUploadAsXxeCandidate() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/personal/CombineExcelUpload", 200,
                Map.of("Content-Type", "multipart/form-data; boundary=xyz"), Map.of(),
                List.of(), "", "", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.XXE));
    }

    @Test
    void flagsBackUrlParamAsOpenRedirectCandidate() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/error", 200,
                Map.of(), Map.of(), List.of("backURL"), "", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.OPEN_REDIRECT));
    }

    @Test
    void flagsAiSessionMissingConstraints() {
        AnalysisContext ctx = TestFixtures.http("generativelanguage.googleapis.com", "POST", "/v1beta/cachedContents", 200,
                Map.of(), Map.of(), List.of(), "",
                "{\"wsUrl\":\"wss://...\",\"token\":\"abc\",\"ttlSeconds\":60}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.AI_SESSION_MISCONFIGURATION));
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
