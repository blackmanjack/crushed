package com.crushed.core;

import burp.api.montoya.core.ToolType;
import com.crushed.model.LiveTaskConfig;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class LiveTaskManagerTest {

    @Test
    void defaultTaskMatchesProxySuiteScope() {
        LiveTaskManager manager = new LiveTaskManager(url -> url.contains("in-scope.com"));

        assertTrue(manager.shouldIngest(ToolType.PROXY, "https://in-scope.com/x"));
        assertFalse(manager.shouldIngest(ToolType.PROXY, "https://out-of-scope.com/x"));
        assertFalse(manager.shouldIngest(ToolType.REPEATER, "https://in-scope.com/x"));
    }

    @Test
    void customTaskUnlocksRepeaterTraffic() {
        LiveTaskManager manager = new LiveTaskManager(url -> false);
        manager.addOrUpdate(new LiveTaskConfig("repeater-task", LiveTaskConfig.TaskType.PASSIVE_ANALYSIS,
                Set.of(ToolType.REPEATER), LiveTaskConfig.UrlScopeMode.EVERYTHING, null, false, true));

        assertTrue(manager.shouldIngest(ToolType.REPEATER, "https://anything.com/x"));
        assertFalse(manager.shouldIngest(ToolType.INTRUDER, "https://anything.com/x"));
    }

    @Test
    void customUrlScopeMatchesRegex() {
        LiveTaskManager manager = new LiveTaskManager(url -> false);
        manager.addOrUpdate(new LiveTaskConfig("custom-task", LiveTaskConfig.TaskType.PASSIVE_ANALYSIS,
                Set.of(ToolType.PROXY), LiveTaskConfig.UrlScopeMode.CUSTOM, "api\\.example\\.com", false, true));

        assertTrue(manager.shouldIngest(ToolType.PROXY, "https://api.example.com/v1"));
        assertFalse(manager.shouldIngest(ToolType.PROXY, "https://other.com/v1"));
    }

    @Test
    void autoConfirmOnlyForActiveConfirmTaskType() {
        LiveTaskManager manager = new LiveTaskManager(url -> true);
        manager.addOrUpdate(new LiveTaskConfig("auto-confirm", LiveTaskConfig.TaskType.PASSIVE_ANALYSIS_PLUS_ACTIVE_CONFIRM,
                Set.of(ToolType.PROXY), LiveTaskConfig.UrlScopeMode.EVERYTHING, null, false, true));

        assertTrue(manager.shouldAutoConfirm(ToolType.PROXY, "https://anything.com/x"));
    }

    @Test
    void deduplicationBlocksSecondOccurrenceOnlyWhenRequested() {
        LiveTaskManager manager = new LiveTaskManager(url -> true);
        manager.addOrUpdate(new LiveTaskConfig("dedup-task", LiveTaskConfig.TaskType.PASSIVE_ANALYSIS,
                Set.of(ToolType.PROXY), LiveTaskConfig.UrlScopeMode.EVERYTHING, null, true, true));

        assertTrue(manager.shouldProceedWithDedup(ToolType.PROXY, "https://x.com/a", "GET /a"));
        assertFalse(manager.shouldProceedWithDedup(ToolType.PROXY, "https://x.com/a", "GET /a"));
    }

    @Test
    void noDedupRequestedAlwaysProceeds() {
        LiveTaskManager manager = new LiveTaskManager(url -> true);

        assertTrue(manager.shouldProceedWithDedup(ToolType.PROXY, "https://x.com/a", "GET /a"));
        assertTrue(manager.shouldProceedWithDedup(ToolType.PROXY, "https://x.com/a", "GET /a"));
    }

    @Test
    void removeDropsTask() {
        LiveTaskManager manager = new LiveTaskManager(url -> false);
        manager.remove("Default (Proxy, Suite scope)");

        assertTrue(manager.all().isEmpty());
    }
}
