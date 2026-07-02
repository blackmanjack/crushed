package com.crushed.ai;

import com.crushed.model.*;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AiAnalystTest {

    @Test
    void redactedSummaryContainsReqIdsAndMasksSecrets() {
        HostNotes hostNotes = new HostNotes("api.example.com");
        Finding finding = new Finding(
                "k", IssueType.JWT_WEAKNESS, "api.example.com GET /me", Severity.MEDIUM, Confidence.FIRM,
                Status.POTENTIAL, OwaspRef.JWT_WEAKNESS,
                "JWT token found: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
                "remediation",
                List.of(Evidence.of(42, Evidence.Source.RESPONSE, 0, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", null))
        );
        hostNotes.addOrMergeFinding(finding);

        AiAnalyst analyst = new AiAnalyst(null, new Redactor(), new ActivityLog());
        String summary = analyst.buildRedactedSummary(hostNotes);

        assertTrue(summary.contains("Req #42"));
        assertFalse(summary.contains("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"));
        assertTrue(summary.contains("[REDACTED]"));
    }

    // Note: analyze()'s network-failure handling (ClaudeClient throwing -> analyze() returning
    // null and logging via ActivityLog) is not covered by a unit test here, since ClaudeClient
    // is a concrete class that makes a real HTTP call with no injection seam in this pass —
    // exercising that path would require either a live network call or a mocking framework,
    // neither of which is set up for this project. buildRedactedSummary (the pure, testable
    // part) is covered above.
}
