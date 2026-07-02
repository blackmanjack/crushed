package com.crushed.core;

import burp.api.montoya.persistence.PersistedObject;
import com.crushed.model.TriageState;
import com.crushed.ui.ActivityLog;

/**
 * Loads/saves TriageStore entries to the Burp project file via Montoya's Persistence API, under
 * a "crushed.triage" child object (dedupeKey -> TriageState name, as strings). Project-scoped,
 * not a global disk file — decisions travel with the Burp project, not the machine.
 */
public final class TriagePersistenceBridge {

    private static final String CHILD_KEY = "crushed.triage";

    private final PersistedObject root;
    private final ActivityLog activityLog;

    public TriagePersistenceBridge(PersistedObject root, ActivityLog activityLog) {
        this.root = root;
        this.activityLog = activityLog;
    }

    public void loadInto(TriageStore store) {
        try {
            PersistedObject child = root.getChildObject(CHILD_KEY);
            if (child == null) return;
            for (String dedupeKey : child.stringKeys()) {
                String value = child.getString(dedupeKey);
                try {
                    store.put(dedupeKey, TriageState.valueOf(value));
                } catch (IllegalArgumentException e) {
                    activityLog.error("TriagePersistenceBridge", -1, "Unknown triage state '" + value + "' for key " + dedupeKey);
                }
            }
        } catch (Exception e) {
            activityLog.error("TriagePersistenceBridge", -1, "Failed to load persisted triage decisions: " + e);
        }
    }

    public void persist(String dedupeKey, TriageState state) {
        try {
            PersistedObject child = root.getChildObject(CHILD_KEY);
            if (child == null) {
                child = PersistedObject.persistedObject();
                root.setChildObject(CHILD_KEY, child);
            }
            if (state == TriageState.NEW) {
                child.deleteString(dedupeKey);
            } else {
                child.setString(dedupeKey, state.name());
            }
        } catch (Exception e) {
            activityLog.error("TriagePersistenceBridge", -1, "Failed to persist triage decision for " + dedupeKey + ": " + e);
        }
    }
}
