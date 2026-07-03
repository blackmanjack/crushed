package com.crushed.core;

import com.crushed.model.WstgCoverageState;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory index of user-set manual WSTG test-case statuses, keyed by WSTG id (e.g.
 * "WSTG-INPV-05"). Montoya-independent so the lookup logic is unit-testable; loading from and
 * writing to the Burp project file is handled by WstgChecklistPersistenceBridge. Mirrors
 * TriageStore's shape exactly.
 */
public final class WstgChecklistStore {

    private final Map<String, WstgCoverageState> byWstgId = new ConcurrentHashMap<>();

    public WstgCoverageState get(String wstgId) {
        return byWstgId.get(wstgId);
    }

    public void put(String wstgId, WstgCoverageState state) {
        if (state == WstgCoverageState.NOT_TESTED) {
            byWstgId.remove(wstgId);
        } else {
            byWstgId.put(wstgId, state);
        }
    }

    public Map<String, WstgCoverageState> all() {
        return Map.copyOf(byWstgId);
    }

    public int size() {
        return byWstgId.size();
    }
}
