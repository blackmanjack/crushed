package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FirebaseDetectorTest {

    private final FirebaseDetector detector = new FirebaseDetector(new ActivityLog());

    @Test
    void confirmsWhenUnauthenticatedQueryReturns200WithData() {
        ReplayResult result = ReplayResult.ok(200, "{\"documents\":[{\"name\":\"customers/5001\"}]}");

        List<Finding> findings = detector.confirm(1, "app.example.com", "demo-project", result);

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void noFindingWhenProperlySecuredWith403() {
        ReplayResult result = ReplayResult.ok(403, "{\"error\":\"Missing or insufficient permissions.\"}");

        List<Finding> findings = detector.confirm(1, "app.example.com", "demo-project", result);

        assertTrue(findings.isEmpty());
    }

    @Test
    void noFindingOnNetworkError() {
        ReplayResult result = ReplayResult.error("connection refused");

        List<Finding> findings = detector.confirm(1, "app.example.com", "demo-project", result);

        assertTrue(findings.isEmpty());
    }
}
