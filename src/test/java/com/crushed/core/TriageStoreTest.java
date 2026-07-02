package com.crushed.core;

import com.crushed.model.TriageState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TriageStoreTest {

    @Test
    void storesAndRetrievesTriageDecision() {
        TriageStore store = new TriageStore();
        store.put("finding-a", TriageState.FALSE_POSITIVE);

        assertEquals(TriageState.FALSE_POSITIVE, store.get("finding-a"));
        assertEquals(1, store.size());
    }

    @Test
    void settingBackToNewRemovesTheEntry() {
        TriageStore store = new TriageStore();
        store.put("finding-a", TriageState.IGNORED);
        store.put("finding-a", TriageState.NEW);

        assertNull(store.get("finding-a"));
        assertEquals(0, store.size());
    }

    @Test
    void unknownKeyReturnsNull() {
        TriageStore store = new TriageStore();
        assertNull(store.get("never-seen"));
    }
}
