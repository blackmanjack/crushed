package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ForbiddenBypassDetectorTest {

    @Test
    void confirmsWhenVariantReturnsLargerNonForbiddenResponse() {
        ForbiddenBypassDetector detector = new ForbiddenBypassDetector(new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /admin", 403, 20,
                variant -> "x-original-url".equals(variant)
                        ? ReplayResult.ok(200, "<html>admin dashboard with a lot of content here</html>")
                        : ReplayResult.ok(403, "Forbidden"));

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void noFindingWhenAllVariantsStayForbidden() {
        ForbiddenBypassDetector detector = new ForbiddenBypassDetector(new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /admin", 403, 20,
                variant -> ReplayResult.ok(403, "Forbidden"));

        assertTrue(findings.isEmpty());
    }
}
