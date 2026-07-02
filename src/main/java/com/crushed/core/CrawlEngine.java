package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.crushed.ui.ActivityLog;

import java.net.URI;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.IntSupplier;

/**
 * DIY crawler + Site Map response backfill. Never uses Burp Pro's Scanner.startCrawl — this is
 * the only crawl mechanism crushed has, on both Community and Pro, and it's what guarantees every
 * crawled/backfilled page runs through crushed's own analyzer pipeline (which Pro's built-in
 * crawler does not do). Gated by Active mode AND the "Crawling" toggle, same two-key pattern used
 * for Identity Diff.
 */
public final class CrawlEngine {

    private final MontoyaApi api;
    private final ScopeGate scopeGate;
    private final HistoryIngestor historyIngestor;
    private final LinkHarvester linkHarvester;
    private final BooleanSupplier activeModeEnabled;
    private final BooleanSupplier crawlEnabled;
    private final IntSupplier maxRequests;
    private final IntSupplier maxDepth;
    private final IntSupplier delayMs;
    private final ActivityLog activityLog;

    public CrawlEngine(MontoyaApi api, ScopeGate scopeGate, HistoryIngestor historyIngestor, LinkHarvester linkHarvester,
                        BooleanSupplier activeModeEnabled, BooleanSupplier crawlEnabled,
                        IntSupplier maxRequests, IntSupplier maxDepth, IntSupplier delayMs, ActivityLog activityLog) {
        this.api = api;
        this.scopeGate = scopeGate;
        this.historyIngestor = historyIngestor;
        this.linkHarvester = linkHarvester;
        this.activeModeEnabled = activeModeEnabled;
        this.crawlEnabled = crawlEnabled;
        this.maxRequests = maxRequests;
        this.maxDepth = maxDepth;
        this.delayMs = delayMs;
        this.activityLog = activityLog;
    }

    private boolean gatesOpen() {
        if (!activeModeEnabled.getAsBoolean() || !crawlEnabled.getAsBoolean()) {
            activityLog.info("CrawlEngine", -1, "Skipped: requires both Active mode and Crawling to be enabled in Settings.");
            return false;
        }
        return true;
    }

    /** Visits every in-scope Site Map node that has no captured response yet, and writes the
     * completed pair back into Burp's own Site Map (Target tab) as well as crushed's pipeline. */
    public void fillMissingSiteMapResponses() {
        if (!gatesOpen()) return;

        int budget = maxRequests.getAsInt();
        int sent = 0;
        List<HttpRequestResponse> nodes = api.siteMap().requestResponses();
        for (HttpRequestResponse node : nodes) {
            if (sent >= budget) {
                activityLog.info("CrawlEngine", -1, "Backfill stopped: request budget (" + budget + ") reached.");
                break;
            }
            if (node.hasResponse() || node.request() == null) continue;
            if (!scopeGate.isInScope(node.request().url())) continue;

            sent += fetchAndIngest(node.request()) ? 1 : 0;
            sleep();
        }
        activityLog.info("CrawlEngine", -1, "Site Map backfill finished: " + sent + " request(s) sent.");
    }

    /** BFS crawl starting from seedUrl, following in-scope links discovered in each fetched page. */
    public void crawl(String seedUrl) {
        if (!gatesOpen()) return;
        if (!scopeGate.isInScope(seedUrl)) {
            activityLog.error("CrawlEngine", -1, "Seed URL is out of scope; refusing to crawl: " + seedUrl);
            return;
        }

        int budget = maxRequests.getAsInt();
        int depthBudget = maxDepth.getAsInt();
        Set<String> visited = new LinkedHashSet<>();
        Deque<String[]> queue = new ArrayDeque<>(); // {url, depth}
        queue.add(new String[]{seedUrl, "0"});
        visited.add(seedUrl);

        int sent = 0;
        while (!queue.isEmpty() && sent < budget) {
            String[] item = queue.poll();
            String url = item[0];
            int depth = Integer.parseInt(item[1]);

            HttpRequest request;
            try {
                request = HttpRequest.httpRequestFromUrl(url);
            } catch (Exception e) {
                activityLog.error("CrawlEngine", -1, "Could not build request for discovered URL " + url + ": " + e);
                continue;
            }

            HttpResponse response = fetchAndIngestReturning(request);
            sent++;
            sleep();
            if (response == null || depth >= depthBudget) continue;

            for (String link : linkHarvester.harvest(response.bodyToString())) {
                String resolved = resolve(url, link);
                if (resolved == null || visited.contains(resolved) || !scopeGate.isInScope(resolved)) continue;
                visited.add(resolved);
                queue.add(new String[]{resolved, String.valueOf(depth + 1)});
            }
        }
        activityLog.info("CrawlEngine", -1, "Crawl finished: " + sent + " request(s) sent, " + visited.size() + " URL(s) discovered.");
    }

    private boolean fetchAndIngest(HttpRequest request) {
        return fetchAndIngestReturning(request) != null;
    }

    private HttpResponse fetchAndIngestReturning(HttpRequest request) {
        try {
            HttpRequestResponse result = api.http().sendRequest(request);
            if (result.response() == null) {
                activityLog.error("CrawlEngine", -1, "No response for " + request.url());
                return null;
            }
            api.siteMap().add(result);
            historyIngestor.ingestFetched(request, result.response(), null);
            activityLog.info("CrawlEngine", -1, "Fetched " + request.url() + " -> " + result.response().statusCode());
            return result.response();
        } catch (Exception e) {
            activityLog.error("CrawlEngine", -1, "Send failed for " + request.url() + ": " + e);
            return null;
        }
    }

    private String resolve(String baseUrl, String link) {
        try {
            return URI.create(baseUrl).resolve(link).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private void sleep() {
        try {
            Thread.sleep(Math.max(0, delayMs.getAsInt()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
