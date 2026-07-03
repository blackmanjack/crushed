package com.crushed.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.crushed.model.Evidence;
import com.crushed.model.Finding;
import com.crushed.model.IssueType;
import com.crushed.model.OwaspRef;
import com.crushed.model.Severity;
import com.crushed.model.Confidence;
import com.crushed.model.Status;
import com.crushed.ui.ActivityLog;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;

/**
 * Active per-host backup/sensitive-file discovery, matching Backup Finder / Interesting Files
 * Scanner / CTFHelper. Reuses CrawlEngine.sendAndIngest(...) (send + Site Map write-back +
 * analyzer pipeline) rather than a fourth parallel sender, so every fetched file also flows
 * through crushed's full passive analyzer set, not just this probe's own 200-status check.
 */
public final class BackupFileProbe {

    private static final List<String> CANDIDATE_PATHS = List.of(
            ".git/config", ".git/HEAD", ".env", ".env.local", ".env.production",
            "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
            "web.config", "web.config.bak", "wp-config.php.bak", "config.php.bak",
            "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "database.sql",
            ".DS_Store", "Thumbs.db", ".htpasswd", ".htaccess",
            "id_rsa", "id_rsa.pub", ".aws/credentials",
            "app.js.bak", "index.php.bak", "index.php.swp", "index.php~",
            "composer.json", "package.json.bak", "yarn.lock.bak",
            "server-status", "phpinfo.php", ".well-known/security.txt"
    );

    private final ScopeGate scopeGate;
    private final CrawlEngine crawlEngine;
    private final BooleanSupplier activeModeEnabled;
    private final ActivityLog activityLog;

    public BackupFileProbe(ScopeGate scopeGate, CrawlEngine crawlEngine, BooleanSupplier activeModeEnabled, ActivityLog activityLog) {
        this.scopeGate = scopeGate;
        this.crawlEngine = crawlEngine;
        this.activeModeEnabled = activeModeEnabled;
        this.activityLog = activityLog;
    }

    /** Probes a small built-in wordlist of common backup/sensitive paths against the given base
     * URL (e.g. "https://app.example.com"), returning a Finding for every hit (2xx response). */
    public List<Finding> probeHost(String baseUrl) {
        if (!activeModeEnabled.getAsBoolean()) {
            activityLog.info("BackupFileProbe", -1, "Skipped: requires Active mode to be enabled in Settings.");
            return List.of();
        }
        if (!scopeGate.isInScope(baseUrl)) {
            activityLog.error("BackupFileProbe", -1, "Host is out of scope; refusing to probe: " + baseUrl);
            return List.of();
        }

        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        List<Finding> findings = new ArrayList<>();

        for (String path : CANDIDATE_PATHS) {
            String url = base + "/" + path;
            HttpRequest request;
            try {
                request = HttpRequest.httpRequestFromUrl(url);
            } catch (Exception e) {
                activityLog.error("BackupFileProbe", -1, "Could not build request for " + url + ": " + e);
                continue;
            }

            HttpResponse response = crawlEngine.sendAndIngest(request);
            if (response == null) continue;
            if (response.statusCode() < 200 || response.statusCode() >= 300) continue;

            String endpointKey = base + " GET /" + path;
            Evidence evidence = Evidence.of(0, Evidence.Source.RESPONSE, 0,
                    "status=" + response.statusCode() + " len=" + response.bodyToString().length(), path);
            findings.add(new Finding(
                    "BACKUP_FILE|" + endpointKey,
                    IssueType.SENSITIVE_INFO_DISCLOSURE,
                    endpointKey,
                    Severity.MEDIUM,
                    Confidence.CERTAIN,
                    Status.CONFIRMED,
                    OwaspRef.SENSITIVE_INFO_DISCLOSURE,
                    "Backup/sensitive file '" + path + "' is publicly accessible (status " + response.statusCode() + ").",
                    RemediationCatalog.forIssueType(IssueType.SENSITIVE_INFO_DISCLOSURE),
                    List.of(evidence)
            ));
            activityLog.bypassed("BackupFileProbe", -1, "Found accessible file: " + url);
        }

        activityLog.info("BackupFileProbe", -1, "Probe finished for " + baseUrl + ": " + findings.size() + " hit(s) out of " + CANDIDATE_PATHS.size() + " candidate path(s).");
        return findings;
    }
}
