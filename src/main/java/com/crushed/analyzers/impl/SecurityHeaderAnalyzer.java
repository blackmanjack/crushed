package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Passive response-header hygiene check, Burp-Pro-style: flags tech-disclosure headers
 * (Server/X-Powered-By/etc.) and missing standard hardening headers (HSTS, X-Content-Type-Options,
 * clickjacking protection, CSP). Only evaluated on HTML-ish responses to avoid firing on every
 * static asset request.
 */
public final class SecurityHeaderAnalyzer implements Analyzer {

    private static final List<String> TECH_DISCLOSURE_HEADERS = List.of(
            "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via");

    @Override
    public String name() {
        return "SecurityHeaderAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String mime = context.responseMimeType() == null ? "" : context.responseMimeType().toLowerCase();
        if (!mime.contains("html")) return List.of();
        Map<String, String> responseHeaders = context.responseHeaders();
        if (responseHeaders == null) return List.of();

        Map<String, String> lower = new HashMap<>();
        for (Map.Entry<String, String> e : responseHeaders.entrySet()) {
            lower.put(e.getKey().toLowerCase(), e.getValue());
        }

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        for (String headerName : TECH_DISCLOSURE_HEADERS) {
            String value = lower.get(headerName);
            if (value == null || value.isBlank()) continue;
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                    headerName + ": " + value, headerName);
            signals.add(new Signal(IssueType.TECH_STACK_DISCLOSURE, endpointKey, Confidence.CERTAIN,
                    "Response header '" + headerName + "' discloses server/technology information: " + value, evidence));
        }

        if (context.isHttps() && !lower.containsKey("strict-transport-security")) {
            signals.add(new Signal(IssueType.MISSING_HSTS, endpointKey, Confidence.CERTAIN,
                    "HTTPS response has no Strict-Transport-Security header — the browser is not instructed to " +
                            "always use HTTPS for this host.", Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                    "Strict-Transport-Security header absent", null)));
        }

        if (!lower.containsKey("x-content-type-options")) {
            signals.add(new Signal(IssueType.MISSING_X_CONTENT_TYPE_OPTIONS, endpointKey, Confidence.CERTAIN,
                    "Response has no X-Content-Type-Options: nosniff header — browsers may MIME-sniff the body " +
                            "away from the declared Content-Type.", Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                    "X-Content-Type-Options header absent", null)));
        }

        boolean hasFrameAncestors = lower.containsKey("content-security-policy")
                && lower.get("content-security-policy").toLowerCase().contains("frame-ancestors");
        if (!lower.containsKey("x-frame-options") && !hasFrameAncestors) {
            signals.add(new Signal(IssueType.MISSING_CLICKJACKING_PROTECTION, endpointKey, Confidence.CERTAIN,
                    "Response has neither X-Frame-Options nor a CSP frame-ancestors directive — the page can be " +
                            "embedded in a frame on an attacker-controlled site (clickjacking).", Evidence.of(context.historyId(),
                    Evidence.Source.RESPONSE, 0, "X-Frame-Options / CSP frame-ancestors absent", null)));
        }

        if (!lower.containsKey("content-security-policy")) {
            signals.add(new Signal(IssueType.MISSING_CSP, endpointKey, Confidence.CERTAIN,
                    "Response has no Content-Security-Policy header — no defense-in-depth restriction on " +
                            "script/style/frame sources.", Evidence.of(context.historyId(), Evidence.Source.RESPONSE, 0,
                    "Content-Security-Policy header absent", null)));
        }

        return signals;
    }
}
