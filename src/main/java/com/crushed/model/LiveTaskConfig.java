package com.crushed.model;

import burp.api.montoya.core.ToolType;

import java.util.Set;

/**
 * Configuration for one "Live Task" — crushed's equivalent of Burp Pro's "New Live Task" wizard
 * (Task type / Tools scope / URL scope / Deduplication). A filter+behavior layer on top of the
 * existing ingestion pipeline, not a second parallel pipeline.
 */
public record LiveTaskConfig(
        String name,
        TaskType taskType,
        Set<ToolType> tools,
        UrlScopeMode urlScopeMode,
        String customUrlPattern,
        boolean deduplicate,
        boolean enabled
) {
    /** PASSIVE_ANALYSIS = today's default behavior (analyzers run, nothing auto-sent).
     * PASSIVE_ANALYSIS_PLUS_ACTIVE_CONFIRM auto-invokes ActiveConfirmationService.confirm(...) on
     * every new finding instead of requiring the manual "Confirm Actively" click — crushed's
     * equivalent of Burp Pro's "Live audit". */
    public enum TaskType { PASSIVE_ANALYSIS, PASSIVE_ANALYSIS_PLUS_ACTIVE_CONFIRM }

    public enum UrlScopeMode { EVERYTHING, SUITE_SCOPE, CUSTOM }

    public static LiveTaskConfig defaultTask() {
        return new LiveTaskConfig("Default (Proxy, Suite scope)", TaskType.PASSIVE_ANALYSIS,
                Set.of(ToolType.PROXY), UrlScopeMode.SUITE_SCOPE, null, false, true);
    }
}
