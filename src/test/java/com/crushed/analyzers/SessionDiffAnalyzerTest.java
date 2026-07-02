package com.crushed.analyzers;

import com.crushed.analyzers.impl.SessionDiffAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SessionDiffAnalyzerTest {

    private final SessionDiffAnalyzer analyzer = new SessionDiffAnalyzer();

    @Test
    void flagsTwoDifferentSessionsGettingSameUserScopedData() {
        AnalysisContext accountA = TestFixtures.http("api.example.com", "GET", "/api/v1/profile/123", 200,
                Map.of("Cookie", "session=account-a-token"), Map.of(), List.of(), "",
                "{\"id\":123,\"name\":\"Alice\",\"balance\":500}", "application/json");
        AnalysisContext accountB = TestFixtures.http("api.example.com", "GET", "/api/v1/profile/123", 200,
                Map.of("Cookie", "session=account-b-token"), Map.of(), List.of(), "",
                "{\"id\":123,\"name\":\"Alice\",\"balance\":500}", "application/json");

        List<Signal> firstPass = analyzer.analyze(accountA, fp(accountA));
        assertTrue(firstPass.isEmpty(), "no prior session recorded yet, nothing to compare against");

        List<Signal> secondPass = analyzer.analyze(accountB, fp(accountB));
        assertTrue(secondPass.stream().anyMatch(s -> s.issueType() == IssueType.IDOR_BOLA));
    }

    @Test
    void doesNotFlagSameSessionSeenTwice() {
        AnalysisContext req1 = TestFixtures.http("api.example.com", "GET", "/api/v1/profile/123", 200,
                Map.of("Cookie", "session=same-token"), Map.of(), List.of(), "", "{\"id\":123}", "application/json");
        AnalysisContext req2 = TestFixtures.http("api.example.com", "GET", "/api/v1/profile/123", 200,
                Map.of("Cookie", "session=same-token"), Map.of(), List.of(), "", "{\"id\":123}", "application/json");

        analyzer.analyze(req1, fp(req1));
        List<Signal> signals = analyzer.analyze(req2, fp(req2));

        assertTrue(signals.isEmpty());
    }

    @Test
    void ignoresEndpointsThatDoNotLookUserScoped() {
        AnalysisContext productsA = TestFixtures.http("api.example.com", "GET", "/api/v1/products", 200,
                Map.of("Cookie", "session=account-a"), Map.of(), List.of(), "", "{\"products\":[]}", "application/json");
        AnalysisContext productsB = TestFixtures.http("api.example.com", "GET", "/api/v1/products", 200,
                Map.of("Cookie", "session=account-b"), Map.of(), List.of(), "", "{\"products\":[]}", "application/json");

        analyzer.analyze(productsA, fp(productsA));
        List<Signal> signals = analyzer.analyze(productsB, fp(productsB));

        assertTrue(signals.isEmpty(), "a public product catalog is expected to look identical across sessions");
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
