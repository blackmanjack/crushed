package com.crushed.identitydiff;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ResponseDifferTest {

    private final ResponseDiffer differ = new ResponseDiffer();

    @Test
    void sameAccessWhenBothSucceedWithSimilarBody() {
        ReplayResult original = ReplayResult.ok(200, "{\"id\":1,\"name\":\"Alice\",\"balance\":100}");
        ReplayResult replay = ReplayResult.ok(200, "{\"id\":1,\"name\":\"Alice\",\"balance\":100}");

        assertEquals(ResponseDiffer.DiffVerdict.SAME_ACCESS, differ.compare(original, replay));
    }

    @Test
    void properlyDeniedWhenReplayIsForbidden() {
        ReplayResult original = ReplayResult.ok(200, "{\"id\":1,\"name\":\"Alice\"}");
        ReplayResult replay = ReplayResult.ok(403, "{\"error\":\"forbidden\"}");

        assertEquals(ResponseDiffer.DiffVerdict.PROPERLY_DENIED, differ.compare(original, replay));
    }

    @Test
    void inconclusiveOnNetworkError() {
        ReplayResult original = ReplayResult.ok(200, "body");
        ReplayResult replay = ReplayResult.error("timeout");

        assertEquals(ResponseDiffer.DiffVerdict.INCONCLUSIVE, differ.compare(original, replay));
    }
}
