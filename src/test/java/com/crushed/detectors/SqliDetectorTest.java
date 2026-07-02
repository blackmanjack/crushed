package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SqliDetectorTest {

    @Test
    void confirmsBooleanBasedSqliWhenResponsesDiffer() {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), new ActivityLog());
        SqliDetector detector = new SqliDetector(bypassEngine, new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /search", "q",
                payload -> payload.contains("'1'='1")
                        ? ReplayResult.ok(200, "<ul><li>Result A</li><li>Result B</li><li>Result C</li></ul>")
                        : ReplayResult.ok(200, "<p>No results found.</p>"));

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void noFindingWhenResponsesAreIdentical() {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), new ActivityLog());
        SqliDetector detector = new SqliDetector(bypassEngine, new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /search", "q",
                payload -> ReplayResult.ok(200, "same response regardless of payload"));

        assertTrue(findings.isEmpty());
    }
}
