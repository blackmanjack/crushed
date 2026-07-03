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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive cookie-attribute check, Burp-Pro-style: for every Set-Cookie header on the response,
 * flags a missing Secure flag (only relevant over HTTPS), missing HttpOnly flag, and a missing
 * or weak SameSite attribute (absent, or SameSite=None without Secure).
 *
 * Parses Set-Cookie lines directly out of {@code context.responseRaw()} rather than
 * {@code context.responseHeaders()}, because the latter is a plain Map keyed by header name and
 * silently collapses multiple Set-Cookie headers on one response to the last value seen.
 */
public final class CookieSecurityAnalyzer implements Analyzer {

    private static final Pattern SET_COOKIE_LINE = Pattern.compile("(?im)^Set-Cookie:\\s*(.+)$");

    @Override
    public String name() {
        return "CookieSecurityAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String responseRaw = context.responseRaw();
        if (responseRaw == null || responseRaw.isEmpty()) return List.of();

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        Matcher matcher = SET_COOKIE_LINE.matcher(responseRaw);
        while (matcher.find()) {
            String cookieLine = matcher.group(1).trim();
            String[] parts = cookieLine.split(";");
            if (parts.length == 0) continue;

            String cookieName = parts[0].split("=", 2)[0].trim();
            if (cookieName.isEmpty()) continue;

            boolean hasSecure = false;
            boolean hasHttpOnly = false;
            String sameSiteValue = null;

            for (int i = 1; i < parts.length; i++) {
                String attr = parts[i].trim();
                if (attr.equalsIgnoreCase("Secure")) {
                    hasSecure = true;
                } else if (attr.equalsIgnoreCase("HttpOnly")) {
                    hasHttpOnly = true;
                } else if (attr.toLowerCase().startsWith("samesite")) {
                    int eq = attr.indexOf('=');
                    sameSiteValue = eq >= 0 ? attr.substring(eq + 1).trim() : "";
                }
            }

            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, matcher.start(),
                    "Set-Cookie: " + cookieLine, cookieName);

            if (context.isHttps() && !hasSecure) {
                signals.add(new Signal(IssueType.COOKIE_MISSING_SECURE_FLAG, endpointKey, Confidence.CERTAIN,
                        "Cookie '" + cookieName + "' is set over HTTPS without the Secure attribute — it may be sent " +
                                "over a future plaintext connection.", evidence));
            }
            if (!hasHttpOnly) {
                signals.add(new Signal(IssueType.COOKIE_MISSING_HTTPONLY_FLAG, endpointKey, Confidence.CERTAIN,
                        "Cookie '" + cookieName + "' has no HttpOnly attribute — it is readable via document.cookie, " +
                                "widening the impact of any XSS.", evidence));
            }
            if (sameSiteValue == null || (sameSiteValue.equalsIgnoreCase("None") && !hasSecure)) {
                signals.add(new Signal(IssueType.COOKIE_MISSING_SAMESITE, endpointKey, Confidence.CERTAIN,
                        sameSiteValue == null
                                ? "Cookie '" + cookieName + "' has no SameSite attribute — defaults vary by browser and offer no guaranteed CSRF protection."
                                : "Cookie '" + cookieName + "' uses SameSite=None without the Secure attribute (invalid combination, browsers will reject or ignore it).",
                        evidence));
            }
        }
        return signals;
    }
}
