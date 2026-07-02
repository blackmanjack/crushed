package com.crushed.core;

import com.crushed.model.TriageState;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory index of user triage decisions (Confirmed/False-Positive/Ignored), keyed by
 * Finding.dedupeKey(). Montoya-independent so the lookup logic is unit-testable; loading from
 * and writing to the Burp project file is handled by TriagePersistenceBridge.
 */
public final class TriageStore {

    private final Map<String, TriageState> byDedupeKey = new ConcurrentHashMap<>();

    public TriageState get(String dedupeKey) {
        return byDedupeKey.get(dedupeKey);
    }

    public void put(String dedupeKey, TriageState state) {
        if (state == TriageState.NEW) {
            byDedupeKey.remove(dedupeKey);
        } else {
            byDedupeKey.put(dedupeKey, state);
        }
    }

    public Map<String, TriageState> all() {
        return Map.copyOf(byDedupeKey);
    }

    public int size() {
        return byDedupeKey.size();
    }
}
