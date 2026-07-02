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
 * Multi-language static source analysis: JS/TS/HTML/ASPX/JSP/PHP bodies in scope are scanned
 * for DOM sinks, user-controlled sources, and hardcoded secrets. Regex-based, not a real
 * taint-tracker (see plan Limitations) — skips bodies over a size cap to stay off the UI thread.
 */
public final class SourceAnalyzer implements Analyzer {

    private static final int MAX_BODY_CHARS = 2_000_000;

    private static final Pattern[] SINKS = {
            Pattern.compile("location\\s*(\\.href|\\.assign|\\.replace)?\\s*="),
            Pattern.compile("innerHTML\\s*="),
            Pattern.compile("outerHTML\\s*="),
            Pattern.compile("document\\.write\\s*\\("),
            Pattern.compile("\\beval\\s*\\("),
            Pattern.compile("setTimeout\\s*\\(\\s*[\"']"),
            Pattern.compile("new\\s+WebSocket\\s*\\(")
    };

    private static final Pattern[] SOURCES = {
            Pattern.compile("location\\.(search|hash|href)"),
            Pattern.compile("document\\.referrer"),
            Pattern.compile("window\\.name"),
            Pattern.compile("Request\\.(QueryString|Form)"),
            Pattern.compile("\\$_(GET|POST|REQUEST)\\b"),
            Pattern.compile("request\\.getParameter\\s*\\(")
    };

    private static final Pattern[] SECRETS = {
            Pattern.compile("AIza[0-9A-Za-z_-]{20,}"),
            Pattern.compile("AKIA[0-9A-Z]{12,}"),
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*"),
            Pattern.compile("(?i)(secret|password|api[_-]?key)\\s*[:=]\\s*[\"'][^\"']{6,}[\"']"),
            Pattern.compile("getTempAWSCreds|getJWTToken|getAuthSession")
    };

    @Override
    public String name() {
        return "SourceAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String body = context.responseBody();
        if (body == null || body.isEmpty()) return List.of();
        if (!isTextSource(context.responseMimeType(), context.path())) return List.of();
        if (body.length() > MAX_BODY_CHARS) return List.of();

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        boolean hasSink = false;
        boolean hasSource = false;
        for (Pattern p : SINKS) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                hasSink = true;
                signals.add(signalFor(context, endpointKey, IssueType.DOM_XSS, Confidence.TENTATIVE,
                        "Potential DOM XSS sink: " + m.group(), body, m.start()));
            }
        }
        for (Pattern p : SOURCES) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                hasSource = true;
                signals.add(signalFor(context, endpointKey, IssueType.DOM_XSS, Confidence.TENTATIVE,
                        "User-controlled source referenced: " + m.group(), body, m.start()));
            }
        }
        for (Pattern p : SECRETS) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                signals.add(signalFor(context, endpointKey, IssueType.SENSITIVE_INFO_DISCLOSURE, Confidence.FIRM,
                        "Possible hardcoded secret/credential pattern found in source.", body, m.start()));
            }
        }

        if (hasSink && hasSource) {
            signals.add(signalFor(context, endpointKey, IssueType.DOM_XSS, Confidence.FIRM,
                    "Both a DOM sink and a user-controlled source were found in the same file — elevated DOM XSS risk.",
                    body, 0));
        }
        return signals;
    }

    private Signal signalFor(AnalysisContext context, String endpointKey, IssueType type, Confidence confidence,
                              String rationale, String body, int offset) {
        int line = com.crushed.core.EvidenceLocator.lineNumberOfOffset(body, offset);
        String snippet = com.crushed.core.EvidenceLocator.snippetAround(body, offset, 60);
        Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, line, snippet, null);
        return new Signal(type, endpointKey, confidence, rationale, evidence);
    }

    private boolean isTextSource(String mimeType, String path) {
        String p = path == null ? "" : path.toLowerCase();
        String m = mimeType == null ? "" : mimeType.toLowerCase();
        return m.contains("html") || m.contains("javascript") || m.contains("json") || m.contains("xml")
                || p.endsWith(".js") || p.endsWith(".ts") || p.endsWith(".map") || p.endsWith(".html")
                || p.endsWith(".aspx") || p.endsWith(".asp") || p.endsWith(".jsp") || p.endsWith(".jspx")
                || p.endsWith(".php") || p.endsWith(".json") || p.endsWith(".xml");
    }
}
