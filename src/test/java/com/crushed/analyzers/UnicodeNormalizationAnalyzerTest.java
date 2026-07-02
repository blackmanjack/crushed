package com.crushed.analyzers;

import com.crushed.analyzers.impl.UnicodeNormalizationAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UnicodeNormalizationAnalyzerTest {

    private final UnicodeNormalizationAnalyzer analyzer = new UnicodeNormalizationAnalyzer();

    @Test
    void flagsMixedCyrillicLatinUsername() {
        // "аdmin" uses Cyrillic 'а' (U+0430) instead of Latin 'a'
        String body = "{\"username\":\"аdmin\"}";
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/register", 200,
                Map.of(), Map.of(), List.of("username"), body, "", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.UNICODE_NORMALIZATION));
    }

    @Test
    void doesNotFlagPlainAscii() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/register", 200,
                Map.of(), Map.of(), List.of("username"), "{\"username\":\"admin\"}", "", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
