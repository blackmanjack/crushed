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
import java.util.regex.Pattern;

/**
 * Passive path-traversal heuristic: a file/path-like parameter already carries a traversal
 * sequence, or the response body looks like a leaked filesystem error/file content for a
 * path-like parameter.
 */
public final class PathTraversalAnalyzer implements Analyzer {

    private static final Set<String> PATH_LIKE_PARAMS = Set.of(
            "file", "path", "filename", "filepath", "doc", "document", "page", "template",
            "include", "load", "dir", "folder", "resource", "img", "image");

    private static final Pattern TRAVERSAL_SEQUENCE = Pattern.compile(
            "\\.\\./|\\.\\.\\\\|%2e%2e|%252e%252e|\\.\\.%2f|\\.\\.%5c", Pattern.CASE_INSENSITIVE);

    private static final Pattern FILE_LEAK_SIGNATURE = Pattern.compile(
            "root:.*:0:0:|\\[boot loader\\]|\\[extensions\\]|/etc/passwd", Pattern.CASE_INSENSITIVE);

    @Override
    public String name() {
        return "PathTraversalAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        if (context.requestParamNames() == null || context.requestParamNames().isEmpty()) return List.of();

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());
        String requestRaw = context.requestRaw() == null ? "" : context.requestRaw();
        String responseBody = context.responseBody() == null ? "" : context.responseBody();

        for (String param : context.requestParamNames()) {
            int valueStart = findParamValue(requestRaw, param);
            if (valueStart < 0) continue;
            String value = extractValue(requestRaw, valueStart);
            boolean pathLikeName = PATH_LIKE_PARAMS.contains(param.toLowerCase());

            if (TRAVERSAL_SEQUENCE.matcher(value).find()) {
                Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, valueStart,
                        "parameter '" + param + "' value contains a traversal sequence: " + value, param);
                signals.add(new Signal(IssueType.PATH_TRAVERSAL, endpointKey, Confidence.TENTATIVE,
                        "Parameter '" + param + "' already carries a directory-traversal sequence in the request.",
                        evidence));
                continue;
            }

            if (pathLikeName && !responseBody.isEmpty()) {
                var m = FILE_LEAK_SIGNATURE.matcher(responseBody);
                if (m.find()) {
                    Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, m.start(),
                            responseBody.substring(Math.max(0, m.start() - 40), Math.min(responseBody.length(), m.end() + 40)),
                            param);
                    signals.add(new Signal(IssueType.PATH_TRAVERSAL, endpointKey, Confidence.TENTATIVE,
                            "File/path-like parameter '" + param + "' correlates with a response that looks like " +
                                    "leaked filesystem content — candidate path traversal.", evidence));
                }
            }
        }
        return signals;
    }

    private int findParamValue(String requestRaw, String param) {
        int idx = requestRaw.indexOf(param + "=");
        return idx < 0 ? -1 : idx + param.length() + 1;
    }

    private String extractValue(String requestRaw, int start) {
        int end = start;
        while (end < requestRaw.length() && "&\r\n ".indexOf(requestRaw.charAt(end)) < 0) end++;
        return requestRaw.substring(start, end);
    }
}
