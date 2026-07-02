package com.crushed.analyzers;

import com.crushed.analyzers.impl.JwtAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class JwtAnalyzerTest {

    private final JwtAnalyzer analyzer = new JwtAnalyzer();

    @Test
    void flagsAlgNoneToken() {
        String header = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"1\",\"exp\":9999999999}".getBytes(StandardCharsets.UTF_8));
        String token = header + "." + payload + ".";

        AnalysisContext ctx = TestFixtures.http("api.example.com", "GET", "/api/me", 200,
                Map.of(), Map.of(), List.of(), "", "{\"token\":\"" + token + "\"}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.JWT_WEAKNESS));
    }

    @Test
    void doesNotCrashOnMalformedToken() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "GET", "/api/me", 200,
                Map.of(), Map.of(), List.of(), "", "eyJhbGciOiJIUzI1NiJ9.not-valid-base64!!!.", "application/json");

        assertDoesNotThrow(() -> analyzer.analyze(ctx, fp(ctx)));
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
