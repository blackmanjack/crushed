package com.crushed.core;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure, stateless extraction of candidate URLs (relative or absolute) from an HTML/JS response
 * body. Resolution against a base URL is the caller's job (CrawlEngine) so this stays testable
 * without any Montoya/URL types.
 */
public final class LinkHarvester {

    private static final Pattern[] PATTERNS = {
            Pattern.compile("href\\s*=\\s*[\"']([^\"'#][^\"']*)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("src\\s*=\\s*[\"']([^\"'#][^\"']*)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("action\\s*=\\s*[\"']([^\"'#][^\"']*)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("fetch\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("axios\\.\\w+\\(\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bimport\\s+[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE),
            Pattern.compile("//#\\s*sourceMappingURL=(\\S+)", Pattern.CASE_INSENSITIVE),
    };

    public List<String> harvest(String body) {
        if (body == null || body.isEmpty()) return List.of();

        LinkedHashSet<String> found = new LinkedHashSet<>();
        for (Pattern pattern : PATTERNS) {
            Matcher m = pattern.matcher(body);
            while (m.find()) {
                String url = m.group(1).trim();
                if (isCandidate(url)) {
                    found.add(url);
                }
            }
        }
        return new ArrayList<>(found);
    }

    private boolean isCandidate(String url) {
        if (url.isEmpty()) return false;
        String lower = url.toLowerCase();
        if (lower.startsWith("javascript:") || lower.startsWith("mailto:") || lower.startsWith("tel:")
                || lower.startsWith("data:")) {
            return false;
        }
        return true;
    }
}
