package com.crushed.ai;

import java.util.regex.Pattern;

/**
 * Masks tokens/secrets/PII before anything is sent to the Anthropic API. This is the boundary
 * that makes the AI module safe-by-default: only redacted summaries/snippets ever leave the
 * extension, never raw traffic.
 */
public final class Redactor {

    private static final Pattern[] SENSITIVE_PATTERNS = {
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*"), // JWT
            Pattern.compile("AKIA[0-9A-Z]{12,}"),                                        // AWS key
            Pattern.compile("AIza[0-9A-Za-z_-]{20,}"),                                   // Google API key
            Pattern.compile("(?i)(Bearer|Authorization:)\\s*[A-Za-z0-9._-]{10,}"),
            Pattern.compile("(?i)(password|secret|api[_-]?key)\\s*[:=]\\s*[\"']?[^\"'\\s,}]{4,}"),
            Pattern.compile("(?i)Cookie:\\s*[^\r\n]+")
    };

    public String redact(String text) {
        if (text == null) return "";
        String result = text;
        for (Pattern p : SENSITIVE_PATTERNS) {
            result = p.matcher(result).replaceAll("[REDACTED]");
        }
        return result;
    }
}
