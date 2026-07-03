package com.crushed.core;

import burp.api.montoya.core.ToolType;
import com.crushed.model.LiveTaskConfig;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Holds the list of configured "Live Tasks" and answers whether a given (tool, url) pair should
 * be ingested / auto-confirmed / deduplicated. Pure logic — takes a suite-scope predicate rather
 * than a live ScopeGate/MontoyaApi, so it's unit-testable without any Montoya instance (ToolType
 * itself is a plain data enum, not something requiring a live Burp session).
 */
public final class LiveTaskManager {

    private final List<LiveTaskConfig> tasks = new CopyOnWriteArrayList<>();
    private final Predicate<String> suiteScopeCheck;
    private final Set<String> seenTemplates = ConcurrentHashMap.newKeySet();

    public LiveTaskManager(Predicate<String> suiteScopeCheck) {
        this.suiteScopeCheck = suiteScopeCheck;
        tasks.add(LiveTaskConfig.defaultTask());
    }

    public List<LiveTaskConfig> all() {
        return List.copyOf(tasks);
    }

    public void addOrUpdate(LiveTaskConfig config) {
        tasks.removeIf(t -> t.name().equals(config.name()));
        tasks.add(config);
    }

    public void remove(String name) {
        tasks.removeIf(t -> t.name().equals(name));
    }

    public boolean shouldIngest(ToolType tool, String url) {
        return tasks.stream().anyMatch(t -> t.enabled() && matches(t, tool, url));
    }

    public boolean shouldAutoConfirm(ToolType tool, String url) {
        return tasks.stream().anyMatch(t -> t.enabled()
                && t.taskType() == LiveTaskConfig.TaskType.PASSIVE_ANALYSIS_PLUS_ACTIVE_CONFIRM
                && matches(t, tool, url));
    }

    /** Returns true if this normalized template should proceed (not a duplicate). Only enforces
     * dedup if at least one matching enabled task requests it; otherwise always proceeds. */
    public boolean shouldProceedWithDedup(ToolType tool, String url, String normalizedTemplate) {
        boolean anyDedupRequested = tasks.stream()
                .anyMatch(t -> t.enabled() && t.deduplicate() && matches(t, tool, url));
        if (!anyDedupRequested) return true;
        return seenTemplates.add(normalizedTemplate);
    }

    private boolean matches(LiveTaskConfig config, ToolType tool, String url) {
        if (!config.tools().contains(tool)) return false;
        return switch (config.urlScopeMode()) {
            case EVERYTHING -> true;
            case SUITE_SCOPE -> suiteScopeCheck.test(url);
            case CUSTOM -> matchesCustomPattern(config.customUrlPattern(), url);
        };
    }

    private boolean matchesCustomPattern(String pattern, String url) {
        if (pattern == null || pattern.isBlank()) return false;
        try {
            return Pattern.compile(pattern).matcher(url).find();
        } catch (Exception e) {
            return false;
        }
    }
}
