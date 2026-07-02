package com.crushed.analyzers;

import com.crushed.analyzers.impl.BusinessLogicAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class BusinessLogicAnalyzerTest {

    private final BusinessLogicAnalyzer analyzer = new BusinessLogicAnalyzer();

    @Test
    void flagsMassAssignmentWhenSensitiveFieldPresentInResponse() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "PUT", "/api/v1/profile/123/phone", 200,
                Map.of("Content-Type", "application/json"), Map.of(),
                List.of("phone_number"),
                "{\"phone_number\":\"+62812\",\"kyc_status\":\"verified\"}",
                "{\"phone_number\":\"+62812\",\"kyc_status\":\"verified\"}",
                "application/json");

        List<Signal> signals = analyzer.analyze(ctx, dummyFingerprint(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.MASS_ASSIGNMENT));
    }

    @Test
    void flagsRaceConditionCandidateForClaimEndpoint() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "POST", "/api/v1/bonus/claim", 200,
                Map.of(), Map.of(), List.of(), "{}", "{}", "application/json");

        List<Signal> signals = analyzer.analyze(ctx, dummyFingerprint(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.RACE_CONDITION_CANDIDATE));
    }

    @Test
    void doesNotCrashOnEmptyBody() {
        AnalysisContext ctx = TestFixtures.http("api.example.com", "GET", "/api/v1/profile/123", 200,
                Map.of(), Map.of(), List.of(), "", "", "application/json");

        assertDoesNotThrow(() -> analyzer.analyze(ctx, dummyFingerprint(ctx)));
    }

    private RequestFingerprint dummyFingerprint(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
