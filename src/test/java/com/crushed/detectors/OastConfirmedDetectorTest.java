package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.IssueType;
import com.crushed.model.Status;
import com.crushed.oast.Interaction;
import com.crushed.oast.OastCorrelator;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

class OastConfirmedDetectorTest {

    @Test
    void registeredProbeIsConfirmedWhenMatchingInteractionArrives() {
        OastCorrelator correlator = new OastCorrelator();
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), new ActivityLog());
        OastConfirmedDetector detector = new OastConfirmedDetector(bypassEngine, correlator, new ActivityLog(), "oast.pro");

        StringBuilder capturedPayload = new StringBuilder();
        detector.probeAsync(1, "api.example.com POST /fetch", IssueType.SSRF, "url param",
                OastConfirmedDetector.ssrfPayload(),
                payload -> {
                    capturedPayload.append(payload);
                    return ReplayResult.ok(200, "ok");
                });

        assertEquals(1, correlator.pendingCount());

        String correlationId = extractCorrelationId(capturedPayload.toString());
        assertNotNull(correlationId);

        List<Finding> findings = correlator.correlate(
                List.of(new Interaction(correlationId, "http", "10.0.0.1", Instant.now(), "raw")));

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
        assertEquals(IssueType.SSRF, findings.get(0).issueType());
    }

    private String extractCorrelationId(String payload) {
        Matcher m = Pattern.compile("http://([a-z0-9]+)\\.oast\\.pro/").matcher(payload);
        return m.find() ? m.group(1) : null;
    }
}
