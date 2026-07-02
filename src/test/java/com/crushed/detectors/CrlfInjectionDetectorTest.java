package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CrlfInjectionDetectorTest {

    @Test
    void confirmsWhenInjectedHeaderAppearsInRawResponseHeaders() {
        CrlfInjectionDetector detector = new CrlfInjectionDetector(new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /redirect", "target", payload -> {
            String marker = payload.substring(payload.indexOf(": ") + 2);
            return ReplayResult.ok(302, "", Map.of("X-Crushed-Crlf", marker));
        });

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void noFindingWhenHeaderNotReflected() {
        CrlfInjectionDetector detector = new CrlfInjectionDetector(new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /redirect", "target",
                payload -> ReplayResult.ok(302, "", Map.of("Location", "/next")));

        assertTrue(findings.isEmpty());
    }
}
