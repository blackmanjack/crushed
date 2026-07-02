package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.List;
import java.util.Set;

/** Passive CSRF: state-changing, cookie-authenticated request without a CSRF token or SameSite protection. */
public final class CsrfAnalyzer implements Analyzer {

    private static final Set<String> STATE_CHANGING = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final Set<String> CSRF_TOKEN_HINTS = Set.of(
            "csrf_token", "csrftoken", "x-csrf-token", "__requestverificationtoken", "xsrf-token");

    @Override
    public String name() {
        return "CsrfAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (!STATE_CHANGING.contains(context.method())) return List.of();

        String authHeader = context.requestHeaders() == null ? null : context.requestHeaders().get("Authorization");
        boolean bearerAuth = authHeader != null && authHeader.startsWith("Bearer");
        boolean cookieAuth = context.requestHeaders() != null && context.requestHeaders().containsKey("Cookie");
        if (bearerAuth || !cookieAuth) return List.of();

        boolean hasCsrfToken = context.requestParamNames() != null && context.requestParamNames().stream()
                .anyMatch(p -> CSRF_TOKEN_HINTS.contains(p.toLowerCase()));
        boolean hasCsrfHeader = context.requestHeaders() != null && context.requestHeaders().keySet().stream()
                .anyMatch(h -> CSRF_TOKEN_HINTS.contains(h.toLowerCase()));

        if (hasCsrfToken || hasCsrfHeader) return List.of();

        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, 0,
                "state-changing " + context.method() + " authenticated via Cookie, no CSRF token/header found", null);

        return List.of(new Signal(
                IssueType.CSRF,
                endpointKey,
                Confidence.TENTATIVE,
                "State-changing request relies purely on cookie-based session with no visible anti-CSRF token.",
                evidence
        ));
    }
}
