package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MassAssignmentDetectorTest {

    private final MassAssignmentDetector detector = new MassAssignmentDetector(new ActivityLog());

    @Test
    void confirmsWhenMarkerPersistsOnFollowUpRead() {
        ReplayResult write = ReplayResult.ok(200, "{\"phone\":\"+62812\"}");
        ReplayResult read = ReplayResult.ok(200, "{\"role\":\"crushed-marker-abc\",\"phone\":\"+62812\"}");

        List<Finding> findings = detector.confirm(1, "api.example.com PUT /profile", "role", "crushed-marker-abc", write, read);

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void confirmsWhenMarkerReflectedInWriteResponseEvenWithoutRead() {
        ReplayResult write = ReplayResult.ok(200, "{\"role\":\"crushed-marker-abc\"}");

        List<Finding> findings = detector.confirm(1, "api.example.com PUT /profile", "role", "crushed-marker-abc", write, null);

        assertEquals(1, findings.size());
    }

    @Test
    void noFindingWhenMarkerNeverPersists() {
        ReplayResult write = ReplayResult.ok(200, "{\"phone\":\"+62812\"}");
        ReplayResult read = ReplayResult.ok(200, "{\"phone\":\"+62812\"}");

        List<Finding> findings = detector.confirm(1, "api.example.com PUT /profile", "role", "crushed-marker-abc", write, read);

        assertTrue(findings.isEmpty());
    }
}
