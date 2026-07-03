package com.crushed.core;

import com.crushed.model.WstgCoverageState;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WstgChecklistStoreTest {

    @Test
    void putAndGetRoundTrips() {
        WstgChecklistStore store = new WstgChecklistStore();
        store.put("WSTG-INPV-05", WstgCoverageState.TESTED_ISSUES_FOUND);

        assertEquals(WstgCoverageState.TESTED_ISSUES_FOUND, store.get("WSTG-INPV-05"));
    }

    @Test
    void puttingNotTestedRemovesEntry() {
        WstgChecklistStore store = new WstgChecklistStore();
        store.put("WSTG-INPV-05", WstgCoverageState.TESTED_NO_ISSUES);
        store.put("WSTG-INPV-05", WstgCoverageState.NOT_TESTED);

        assertNull(store.get("WSTG-INPV-05"));
        assertEquals(0, store.size());
    }

    @Test
    void unknownIdReturnsNull() {
        WstgChecklistStore store = new WstgChecklistStore();

        assertNull(store.get("WSTG-UNKNOWN-01"));
    }
}
