package com.crushed.recon;

import com.crushed.ui.ActivityLog;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class YandexDorkerTest {

    @Test
    void extractsDedupesFiltersAndClassifiesLeads() {
        ActivityLog activityLog = new ActivityLog();
        YandexDorker dorker = new YandexDorker(new DorkQueryBuilder(), new UrlClassifier(),
                query -> "<a href=\"https://example.com/api/v1/users\">link</a> " +
                        "<a href=\"https://example.com/api/v1/users\">dup</a> " +
                        "<a href=\"https://out-of-scope.com/admin\">other-domain</a>",
                activityLog);

        List<Lead> leads = dorker.run("example.com", url -> url.contains("example.com"));

        assertEquals(1, leads.size(), "duplicate URL across dork queries should be deduped");
        assertEquals("https://example.com/api/v1/users", leads.get(0).url());
        assertEquals(Lead.Bucket.API, leads.get(0).bucket());
        assertFalse(leads.get(0).verified(), "leads must always start unverified");
        assertEquals("YANDEX", leads.get(0).source());
    }

    @Test
    void continuesAfterOneQueryFails() {
        ActivityLog activityLog = new ActivityLog();
        YandexDorker dorker = new YandexDorker(new DorkQueryBuilder(), new UrlClassifier(),
                query -> {
                    if (query.contains("graphql")) throw new RuntimeException("network error");
                    return "<a href=\"https://example.com/admin/login\">x</a>";
                },
                activityLog);

        List<Lead> leads = dorker.run("example.com", url -> true);

        assertFalse(leads.isEmpty(), "a failing query should not abort the whole recon run");
        assertTrue(activityLog.snapshot().stream().anyMatch(e -> e.level() == ActivityLog.Level.ERROR));
    }

    @Test
    void neverIncludesOutOfScopeUrls() {
        YandexDorker dorker = new YandexDorker(new DorkQueryBuilder(), new UrlClassifier(),
                query -> "<a href=\"https://example.com/admin\">a</a> <a href=\"https://evil.com/admin\">b</a>",
                new ActivityLog());

        List<Lead> leads = dorker.run("example.com", url -> url.startsWith("https://example.com"));

        assertTrue(leads.stream().allMatch(l -> l.url().startsWith("https://example.com")));
    }
}
