package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.core.SessionFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Passive multi-account session/cookie differential detector: if traffic captured in Burp
 * history already contains requests to the SAME endpoint made under two DIFFERENT
 * cookies/session tokens (e.g. the user browsed logged in as Account A and Account B), and
 * both sessions received near-identical, successful responses on a user-scoped endpoint, that
 * is direct evidence of missing per-user authorization — no active replay required, because the
 * evidence was already produced by real traffic.
 *
 * Scoped to endpoints that look user-specific (numeric id in path, or a sensitive-keyword path)
 * to avoid flagging legitimately-shared public endpoints (e.g. a product catalog) where two
 * sessions getting the same response is expected and not a bug.
 */
public final class SessionDiffAnalyzer implements Analyzer {

    private static final Set<String> SENSITIVE_PATH_KEYWORDS = Set.of(
            "profile", "account", "me", "user", "users", "settings", "orders", "order",
            "dashboard", "balance", "wallet", "billing", "invoice", "kyc", "benefits");

    // endpointKey -> (sessionFingerprint -> last observed response snapshot)
    private final Map<String, Map<String, Snapshot>> observedBySession = new ConcurrentHashMap<>();

    private record Snapshot(int historyId, int statusCode, int bodyLength) {
    }

    @Override
    public String name() {
        return "SessionDiffAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.responseStatusCode() < 200 || context.responseStatusCode() >= 300) return List.of();

        String pathTemplate = RequestFingerprint.normalizePathTemplate(context.path());
        if (!looksUserScoped(context.path(), pathTemplate)) return List.of();

        String sessionFingerprint = SessionFingerprint.extract(context.requestHeaders());
        if (sessionFingerprint == null) return List.of();

        String endpointKey = context.host() + " " + context.method() + " " + pathTemplate;
        Map<String, Snapshot> bucket = observedBySession.computeIfAbsent(endpointKey, k -> new ConcurrentHashMap<>());

        String body = context.responseBody() == null ? "" : context.responseBody();
        Snapshot mine = new Snapshot(context.historyId(), context.responseStatusCode(), body.length());

        List<Signal> signals = new ArrayList<>();
        for (Map.Entry<String, Snapshot> entry : bucket.entrySet()) {
            if (entry.getKey().equals(sessionFingerprint)) continue;
            Snapshot other = entry.getValue();
            if (isSimilar(mine, other)) {
                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                        "Session '" + sessionFingerprint + "' got a response indistinguishable from session '"
                                + entry.getKey() + "' (Req #" + other.historyId() + ") on the same user-scoped endpoint.",
                        null);
                signals.add(new Signal(
                        IssueType.IDOR_BOLA,
                        endpointKey,
                        Confidence.FIRM,
                        "Two different logged-in sessions/accounts received near-identical responses from a " +
                                "user-scoped endpoint — this is direct evidence (not a guess) of a possible missing " +
                                "per-user authorization check.",
                        evidence
                ));
            }
        }
        bucket.put(sessionFingerprint, mine);
        return signals;
    }

    private boolean looksUserScoped(String rawPath, String pathTemplate) {
        String p = rawPath == null ? "" : rawPath.toLowerCase();
        if (pathTemplate.contains("{id}")) return true;
        for (String keyword : SENSITIVE_PATH_KEYWORDS) {
            if (p.contains(keyword)) return true;
        }
        return false;
    }

    private boolean isSimilar(Snapshot a, Snapshot b) {
        if (a.statusCode() != b.statusCode()) return false;
        int longer = Math.max(a.bodyLength(), b.bodyLength());
        int shorter = Math.min(a.bodyLength(), b.bodyLength());
        if (longer == 0) return true;
        return ((double) shorter / longer) >= 0.85;
    }

}
