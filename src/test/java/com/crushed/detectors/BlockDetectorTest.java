package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BlockDetectorTest {

    private final BlockDetector detector = new BlockDetector();

    @Test
    void classifiesForbiddenStatusAsBlocked() {
        assertEquals(BlockDetector.Verdict.BLOCKED, detector.classify(ReplayResult.ok(403, "nope")));
    }

    @Test
    void classifiesWafSignatureBodyAsBlocked() {
        assertEquals(BlockDetector.Verdict.BLOCKED, detector.classify(ReplayResult.ok(200, "Request blocked by Web Application Firewall")));
    }

    @Test
    void classifiesNetworkErrorAsError() {
        assertEquals(BlockDetector.Verdict.ERROR, detector.classify(ReplayResult.error("timeout")));
    }

    @Test
    void classifiesServerErrorAsError() {
        assertEquals(BlockDetector.Verdict.ERROR, detector.classify(ReplayResult.ok(502, "bad gateway")));
    }

    @Test
    void classifiesOrdinaryResponseAsNormal() {
        assertEquals(BlockDetector.Verdict.NORMAL, detector.classify(ReplayResult.ok(200, "hello world")));
    }
}
