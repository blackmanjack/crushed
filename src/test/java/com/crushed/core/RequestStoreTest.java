package com.crushed.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RequestStoreTest {

    @Test
    void mintsIncreasingIdsAndRetrievesStoredPair() {
        RequestStore store = new RequestStore();

        int id1 = store.record(null, null);
        int id2 = store.record(null, null);

        assertNotEquals(id1, id2);
        assertEquals(2, store.size());
        assertNotNull(store.get(id1));
        assertNotNull(store.get(id2));
    }

    @Test
    void unknownIdReturnsNull() {
        RequestStore store = new RequestStore();
        assertNull(store.get(999));
    }
}
