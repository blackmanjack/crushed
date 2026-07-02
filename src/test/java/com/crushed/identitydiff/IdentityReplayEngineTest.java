package com.crushed.identitydiff;

import com.crushed.model.Finding;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IdentityReplayEngineTest {

    @Test
    void confirmsBolaWhenAlternateIdentityGetsSameAccess() {
        RequestSender sender = req -> ReplayResult.ok(200, "{\"id\":1,\"name\":\"Alice\",\"balance\":100}");
        IdentityReplayEngine engine = new IdentityReplayEngine(sender, new ResponseDiffer(), new ActivityLog());

        ReplayableRequest original = new ReplayableRequest(1, "api.example.com", "GET", "/api/users/1",
                Map.of("Cookie", "session=owner"), "");
        ReplayResult originalResult = ReplayResult.ok(200, "{\"id\":1,\"name\":\"Alice\",\"balance\":100}");
        Identity lowPrivIdentity = new Identity("low-priv-user", null, "session=attacker");

        List<Finding> findings = engine.replayWithIdentity(original, originalResult, lowPrivIdentity);

        assertEquals(1, findings.size());
        assertEquals(Status.CONFIRMED, findings.get(0).status());
    }

    @Test
    void noFindingWhenAlternateIdentityIsDenied() {
        RequestSender sender = req -> ReplayResult.ok(403, "{\"error\":\"forbidden\"}");
        IdentityReplayEngine engine = new IdentityReplayEngine(sender, new ResponseDiffer(), new ActivityLog());

        ReplayableRequest original = new ReplayableRequest(1, "api.example.com", "GET", "/api/users/1",
                Map.of("Cookie", "session=owner"), "");
        ReplayResult originalResult = ReplayResult.ok(200, "{\"id\":1,\"name\":\"Alice\"}");
        Identity lowPrivIdentity = new Identity("low-priv-user", null, "session=attacker");

        List<Finding> findings = engine.replayWithIdentity(original, originalResult, lowPrivIdentity);

        assertTrue(findings.isEmpty());
    }

    @Test
    void networkErrorDoesNotThrowAndProducesNoFinding() {
        RequestSender sender = req -> { throw new RuntimeException("connection reset"); };
        ActivityLog activityLog = new ActivityLog();
        IdentityReplayEngine engine = new IdentityReplayEngine(sender, new ResponseDiffer(), activityLog);

        ReplayableRequest original = new ReplayableRequest(1, "api.example.com", "GET", "/api/users/1",
                Map.of("Cookie", "session=owner"), "");
        ReplayResult originalResult = ReplayResult.ok(200, "{}");
        Identity identity = new Identity("low-priv-user", null, "session=attacker");

        List<Finding> findings = assertDoesNotThrow(() -> engine.replayWithIdentity(original, originalResult, identity));

        assertTrue(findings.isEmpty());
        assertTrue(activityLog.snapshot().stream().anyMatch(e -> e.module().equals("IdentityReplayEngine")));
    }
}
