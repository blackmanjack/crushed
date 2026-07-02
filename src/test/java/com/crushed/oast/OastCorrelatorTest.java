package com.crushed.oast;

import com.crushed.model.IssueType;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OastCorrelatorTest {

    @Test
    void matchingInteractionConfirmsFinding() {
        OastCorrelator correlator = new OastCorrelator();
        correlator.registerProbe(new PendingProbe("abc123", 42, "api.example.com POST /upload",
                IssueType.XXE, "DOCTYPE entity to OAST domain"));

        Interaction interaction = new Interaction("abc123", "dns", "1.2.3.4", Instant.now(), "raw");

        List<Finding> findings = correlator.correlate(List.of(interaction));

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
        assertEquals(IssueType.XXE, findings.get(0).issueType());
    }

    @Test
    void unmatchedInteractionProducesNoFinding() {
        OastCorrelator correlator = new OastCorrelator();
        correlator.registerProbe(new PendingProbe("known-id", 1, "endpoint", IssueType.SSRF, "url param"));

        Interaction unrelated = new Interaction("unknown-id", "http", "5.6.7.8", Instant.now(), "raw");

        List<Finding> findings = correlator.correlate(List.of(unrelated));

        assertTrue(findings.isEmpty());
    }
}
