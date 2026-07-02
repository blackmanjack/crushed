package com.crushed.detectors;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class FirebaseProjectIdExtractorTest {

    private final FirebaseProjectIdExtractor extractor = new FirebaseProjectIdExtractor();

    @Test
    void extractsFromInitJsonBody() {
        String body = "{\"projectId\":\"demo-lending-app\",\"appId\":\"1:123:web:abc\"}";
        Optional<String> result = extractor.extract(body, null);
        assertEquals("demo-lending-app", result.orElseThrow());
    }

    @Test
    void extractsFromFirestoreRestPath() {
        String path = "/v1/projects/demo-lending-app/databases/(default)/documents/customers/5001";
        Optional<String> result = extractor.extract(null, path);
        assertEquals("demo-lending-app", result.orElseThrow());
    }

    @Test
    void bodyTakesPriorityOverPath() {
        String body = "{\"projectId\":\"from-body\"}";
        String path = "/v1/projects/from-path/databases/(default)/documents";
        Optional<String> result = extractor.extract(body, path);
        assertEquals("from-body", result.orElseThrow());
    }

    @Test
    void returnsEmptyWhenNeitherSourceHasIt() {
        assertTrue(extractor.extract("{\"unrelated\":true}", "/some/other/path").isEmpty());
    }
}
