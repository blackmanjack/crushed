package com.crushed.core;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;
import com.crushed.model.TriageState;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AnalysisPipelineTest {

    @Test
    void growingHistoryAddsEndpointsIdempotently() {
        EndpointRegistry registry = new EndpointRegistry();
        AnalysisPipeline pipeline = new AnalysisPipeline(registry, List.of(), null, new ActivityLog());

        AnalysisContext ctx1 = AnalysisContext.http(1, "api.example.com", "GET", "/api/v1/users/1", "", "", 200,
                Map.of(), Map.of(), List.of(), "", "", "application/json");
        AnalysisContext ctx2 = AnalysisContext.http(2, "api.example.com", "GET", "/api/v1/users/2", "", "", 200,
                Map.of(), Map.of(), List.of(), "", "", "application/json");

        pipeline.process(ctx1);
        pipeline.process(ctx2);

        HostNotes hostNotes = registry.hostNotesFor("api.example.com");
        assertEquals(1, hostNotes.endpoints().size(), "same path template should merge into one endpoint entry");
    }

    @Test
    void faultyAnalyzerDoesNotCrashPipelineAndIsReported() {
        EndpointRegistry registry = new EndpointRegistry();
        ActivityLog activityLog = new ActivityLog();
        Analyzer throwingAnalyzer = new Analyzer() {
            @Override
            public String name() {
                return "ThrowingAnalyzer";
            }

            @Override
            public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
                throw new RuntimeException("boom");
            }
        };
        AnalysisPipeline pipeline = new AnalysisPipeline(registry, List.of(throwingAnalyzer), null, activityLog);

        AnalysisContext ctx = AnalysisContext.http(1, "api.example.com", "GET", "/x", "", "", 200,
                Map.of(), Map.of(), List.of(), "", "", "application/json");

        assertDoesNotThrow(() -> pipeline.process(ctx));
        assertTrue(activityLog.snapshot().stream().anyMatch(e -> e.module().equals("ThrowingAnalyzer")));
    }

    @Test
    void appliesPersistedTriageStateToNewlyCreatedFindings() {
        EndpointRegistry registry = new EndpointRegistry();
        TriageStore triageStore = new TriageStore();

        Analyzer flaggingAnalyzer = new Analyzer() {
            @Override
            public String name() {
                return "FlaggingAnalyzer";
            }

            @Override
            public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
                return List.of(new Signal(IssueType.CSRF, "api.example.com GET /x", Confidence.TENTATIVE,
                        "rationale", Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0, "snippet", null)));
            }
        };

        // Pre-populate the dedupeKey this analyzer will produce, as if the user had already
        // marked it a false positive before restarting Burp.
        String dedupeKey = IssueType.CSRF + "|api.example.com GET /x|null";
        triageStore.put(dedupeKey, TriageState.FALSE_POSITIVE);

        AnalysisPipeline pipeline = new AnalysisPipeline(registry, List.of(flaggingAnalyzer), null, new ActivityLog(), triageStore);

        AnalysisContext ctx = AnalysisContext.http(1, "api.example.com", "GET", "/x", "", "", 200,
                Map.of(), Map.of(), List.of(), "", "", "application/json");
        pipeline.process(ctx);

        HostNotes hostNotes = registry.hostNotesFor("api.example.com");
        Finding finding = hostNotes.allFindings().iterator().next();
        assertEquals(TriageState.FALSE_POSITIVE, finding.triageState());
    }
}
