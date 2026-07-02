package com.crushed.ui;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory, UI-agnostic activity/error log. Every swallowed-would-be exception across the
 * extension is recorded here so nothing fails silently. CrushedTab renders this; unit tests
 * can assert against it directly without touching Swing.
 */
public final class ActivityLog {

    public enum Level { INFO, BLOCKED, BYPASSED, ERROR }

    public record Entry(Instant time, Level level, String module, int historyId, String message) {
    }

    private final List<Entry> entries = new CopyOnWriteArrayList<>();
    private static final int MAX_ENTRIES = 5000;

    public void info(String module, int historyId, String message) {
        add(Level.INFO, module, historyId, message);
    }

    public void error(String module, int historyId, String message) {
        add(Level.ERROR, module, historyId, message);
    }

    public void blocked(String module, int historyId, String message) {
        add(Level.BLOCKED, module, historyId, message);
    }

    public void bypassed(String module, int historyId, String message) {
        add(Level.BYPASSED, module, historyId, message);
    }

    private void add(Level level, String module, int historyId, String message) {
        entries.add(new Entry(Instant.now(), level, module, historyId, message));
        while (entries.size() > MAX_ENTRIES) {
            entries.remove(0);
        }
    }

    public List<Entry> snapshot() {
        return Collections.unmodifiableList(entries);
    }
}
