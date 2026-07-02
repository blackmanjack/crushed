package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PathTraversalDetectorTest {

    @Test
    void confirmsWhenPasswdContentLeaks() {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), new ActivityLog());
        PathTraversalDetector detector = new PathTraversalDetector(bypassEngine, new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /download", "file",
                payload -> ReplayResult.ok(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin"));

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void noFindingWhenResponseIsBenign() {
        WafBypassEngine bypassEngine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), new ActivityLog());
        PathTraversalDetector detector = new PathTraversalDetector(bypassEngine, new ActivityLog());

        List<Finding> findings = detector.probe(1, "api.example.com GET /download", "file",
                payload -> ReplayResult.ok(404, "Not Found"));

        assertTrue(findings.isEmpty());
    }
}
