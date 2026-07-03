package com.crushed.core;

import burp.api.montoya.persistence.PersistedObject;
import com.crushed.model.WstgCoverageState;
import com.crushed.ui.ActivityLog;

/**
 * Loads/saves WstgChecklistStore entries to the Burp project file via Montoya's Persistence API,
 * under a "crushed.wstg" child object (wstgId -> WstgCoverageState name, as strings).
 * Project-scoped, same shape as TriagePersistenceBridge.
 */
public final class WstgChecklistPersistenceBridge {

    private static final String CHILD_KEY = "crushed.wstg";

    private final PersistedObject root;
    private final ActivityLog activityLog;

    public WstgChecklistPersistenceBridge(PersistedObject root, ActivityLog activityLog) {
        this.root = root;
        this.activityLog = activityLog;
    }

    public void loadInto(WstgChecklistStore store) {
        try {
            PersistedObject child = root.getChildObject(CHILD_KEY);
            if (child == null) return;
            for (String wstgId : child.stringKeys()) {
                String value = child.getString(wstgId);
                try {
                    store.put(wstgId, WstgCoverageState.valueOf(value));
                } catch (IllegalArgumentException e) {
                    activityLog.error("WstgChecklistPersistenceBridge", -1, "Unknown WSTG state '" + value + "' for id " + wstgId);
                }
            }
        } catch (Exception e) {
            activityLog.error("WstgChecklistPersistenceBridge", -1, "Failed to load persisted WSTG checklist state: " + e);
        }
    }

    public void persist(String wstgId, WstgCoverageState state) {
        try {
            PersistedObject child = root.getChildObject(CHILD_KEY);
            if (child == null) {
                child = PersistedObject.persistedObject();
                root.setChildObject(CHILD_KEY, child);
            }
            if (state == WstgCoverageState.NOT_TESTED) {
                child.deleteString(wstgId);
            } else {
                child.setString(wstgId, state.name());
            }
        } catch (Exception e) {
            activityLog.error("WstgChecklistPersistenceBridge", -1, "Failed to persist WSTG state for " + wstgId + ": " + e);
        }
    }
}
