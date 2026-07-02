package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Passive OAuth/OIDC authorization-request heuristic. Flags missing state (CSRF-in-flow risk),
 * the implicit flow / id_token without nonce (token leakage via referrer/history), and missing
 * PKCE alongside the authorization-code flow. Passive-only by design: OAuth misconfiguration is
 * a flow-level judgment call, not something an automated single-request probe can confirm.
 */
public final class OAuthAnalyzer implements Analyzer {

    private static final Set<String> AUTH_PATH_HINTS = Set.of("authorize", "oauth", "auth");

    @Override
    public String name() {
        return "OAuthAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String path = context.path() == null ? "" : context.path().toLowerCase();
        List<String> paramNames = context.requestParamNames();
        if (paramNames == null || paramNames.isEmpty()) return List.of();

        boolean pathLooksLikeAuth = AUTH_PATH_HINTS.stream().anyMatch(path::contains);
        boolean hasCoreParams = paramNames.contains("response_type") || paramNames.contains("client_id");
        if (!pathLooksLikeAuth && !hasCoreParams) return List.of();
        if (!paramNames.contains("response_type")) return List.of();

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        String requestRaw = context.requestRaw() == null ? "" : context.requestRaw();

        String responseType = paramValue(requestRaw, "response_type");

        if (!paramNames.contains("state")) {
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                    "authorization request missing 'state' parameter", "state");
            signals.add(new Signal(IssueType.OAUTH_MISCONFIGURATION, endpointKey, Confidence.TENTATIVE,
                    "OAuth/OIDC authorization request has no 'state' parameter — vulnerable to CSRF within the " +
                            "authorization flow.", evidence));
        }

        if ("token".equalsIgnoreCase(responseType) ||
                ("id_token".equalsIgnoreCase(responseType) && !paramNames.contains("nonce"))) {
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                    "response_type=" + responseType, "response_type");
            signals.add(new Signal(IssueType.OAUTH_MISCONFIGURATION, endpointKey, Confidence.TENTATIVE,
                    "OAuth/OIDC implicit flow in use (response_type=" + responseType + ") — tokens are exposed via " +
                            "the URL fragment/browser history/referrer; prefer the authorization-code flow with PKCE.",
                    evidence));
        }

        if ("code".equalsIgnoreCase(responseType) && !paramNames.contains("code_challenge")) {
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                    "authorization-code request missing 'code_challenge'", "code_challenge");
            signals.add(new Signal(IssueType.OAUTH_MISCONFIGURATION, endpointKey, Confidence.TENTATIVE,
                    "Authorization-code flow without PKCE (no 'code_challenge') — recommended for all clients, " +
                            "required for public/mobile/SPA clients.", evidence));
        }

        return signals;
    }

    private String paramValue(String requestRaw, String param) {
        int idx = requestRaw.indexOf(param + "=");
        if (idx < 0) return "";
        int start = idx + param.length() + 1;
        int end = start;
        while (end < requestRaw.length() && "&\r\n ".indexOf(requestRaw.charAt(end)) < 0) end++;
        return requestRaw.substring(start, end);
    }
}
