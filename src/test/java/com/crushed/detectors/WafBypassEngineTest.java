package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WafBypassEngineTest {

    @Test
    void autoRetriesAfterBlockAndSucceedsOnVariant() {
        ActivityLog activityLog = new ActivityLog();
        WafBypassEngine engine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), activityLog);

        // Pure payload gets 403'd; any obfuscated variant (different from the pure payload) passes and is "confirmed".
        String purePayload = "<script>alert(1)</script>";
        WafBypassEngine.Outcome outcome = engine.sendWithAutoBypass(1, "TestDetector", purePayload,
                payload -> payload.equals(purePayload) ? ReplayResult.ok(403, "blocked") : ReplayResult.ok(200, "reflected:" + payload),
                result -> result.statusCode() == 200 && result.body().contains("reflected"));

        assertTrue(outcome.confirmed());
        assertNotNull(outcome.techniqueUsed());
        assertTrue(activityLog.snapshot().stream().anyMatch(e -> e.level() == ActivityLog.Level.BLOCKED));
        assertTrue(activityLog.snapshot().stream().anyMatch(e -> e.level() == ActivityLog.Level.BYPASSED));
    }

    @Test
    void stopsImmediatelyOnNetworkErrorWithoutTryingVariants() {
        ActivityLog activityLog = new ActivityLog();
        WafBypassEngine engine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), activityLog);

        WafBypassEngine.Outcome outcome = engine.sendWithAutoBypass(1, "TestDetector", "payload",
                payload -> ReplayResult.error("connection reset"),
                result -> false);

        assertFalse(outcome.confirmed());
        // Only the pure-payload attempt should have been logged as an error; no BLOCKED entries follow it.
        long errorCount = activityLog.snapshot().stream().filter(e -> e.level() == ActivityLog.Level.ERROR).count();
        assertEquals(1, errorCount);
    }

    @Test
    void allVariantsExhaustedWithoutConfirmationReturnsNotConfirmed() {
        ActivityLog activityLog = new ActivityLog();
        WafBypassEngine engine = new WafBypassEngine(new BlockDetector(), new PayloadVariantGenerator(), activityLog);

        WafBypassEngine.Outcome outcome = engine.sendWithAutoBypass(1, "TestDetector", "payload",
                payload -> ReplayResult.ok(403, "always blocked"),
                result -> true);

        assertFalse(outcome.confirmed());
    }
}
