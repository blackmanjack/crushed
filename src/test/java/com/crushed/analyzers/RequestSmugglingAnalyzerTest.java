package com.crushed.analyzers;

import com.crushed.analyzers.impl.RequestSmugglingAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RequestSmugglingAnalyzerTest {

    private final RequestSmugglingAnalyzer analyzer = new RequestSmugglingAnalyzer();

    @Test
    void flagsBothContentLengthAndTransferEncoding() {
        Map<String, String> reqHeaders = Map.of("Content-Length", "10", "Transfer-Encoding", "chunked");
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/", 200,
                reqHeaders, Map.of(), List.of(), "", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.REQUEST_SMUGGLING_CANDIDATE));
    }

    @Test
    void flagsObfuscatedTransferEncoding() {
        Map<String, String> reqHeaders = Map.of("Transfer-Encoding", "chunked, identity");
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/", 200,
                reqHeaders, Map.of(), List.of(), "", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.REQUEST_SMUGGLING_CANDIDATE));
    }

    @Test
    void ignoresPlainChunkedOnly() {
        Map<String, String> reqHeaders = Map.of("Transfer-Encoding", "chunked");
        AnalysisContext ctx = TestFixtures.http("app.example.com", "POST", "/", 200,
                reqHeaders, Map.of(), List.of(), "", "", "text/html");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
