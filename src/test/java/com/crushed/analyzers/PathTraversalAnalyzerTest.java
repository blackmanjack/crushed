package com.crushed.analyzers;

import com.crushed.analyzers.impl.PathTraversalAnalyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PathTraversalAnalyzerTest {

    private final PathTraversalAnalyzer analyzer = new PathTraversalAnalyzer();

    @Test
    void flagsTraversalSequenceInRequest() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/download", 200,
                Map.of(), Map.of(), List.of("file"), "file=../../../../etc/passwd", "", "application/octet-stream");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.PATH_TRAVERSAL));
    }

    @Test
    void flagsLeakedPasswdContentForPathLikeParam() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/download", 200,
                Map.of(), Map.of(), List.of("file"), "file=report.pdf",
                "root:x:0:0:root:/root:/bin/bash", "text/plain");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.stream().anyMatch(s -> s.issueType() == IssueType.PATH_TRAVERSAL));
    }

    @Test
    void ignoresBenignRequest() {
        AnalysisContext ctx = TestFixtures.http("app.example.com", "GET", "/download", 200,
                Map.of(), Map.of(), List.of("file"), "file=report.pdf", "ok", "text/plain");

        List<Signal> signals = analyzer.analyze(ctx, fp(ctx));

        assertTrue(signals.isEmpty());
    }

    private RequestFingerprint fp(AnalysisContext ctx) {
        return new RequestFingerprint(ctx.host(), ctx.method(), ctx.path(), Set.copyOf(ctx.requestParamNames()),
                null, ctx.responseMimeType(), ctx.responseMimeType(), ctx.responseStatusCode());
    }
}
