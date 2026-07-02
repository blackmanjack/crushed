package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class XssDetectorTest {

    @Test
    void confirmsReflectedXssWhenCanaryReflectedUnencoded() {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), new ActivityLog());
        XssDetector detector = new XssDetector(bypassEngine, new ActivityLog());

        List<Finding> findings = detector.probe(1, "app.example.com GET /search", "q",
                payload -> ReplayResult.ok(200, "<html><body>You searched for: " + payload + "</body></html>"));

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void noFindingWhenPayloadIsEncoded() {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), new ActivityLog());
        XssDetector detector = new XssDetector(bypassEngine, new ActivityLog());

        List<Finding> findings = detector.probe(1, "app.example.com GET /search", "q",
                payload -> ReplayResult.ok(200, "<html><body>You searched for: &lt;encoded&gt;</body></html>"));

        assertTrue(findings.isEmpty());
    }
}
