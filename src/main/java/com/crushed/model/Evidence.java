package com.crushed.model;

/** A precise pointer back to the traffic that produced a signal/finding. */
public record Evidence(
        int historyId,
        Source source,
        int lineOrOffset,
        String snippet,
        String paramOrFieldName
) {
    public enum Source { REQUEST, RESPONSE, WS_FRAME }

    public static Evidence of(int historyId, Source source, int lineOrOffset, String snippet, String paramName) {
        String safeSnippet = snippet == null ? "" : snippet;
        if (safeSnippet.length() > 400) {
            safeSnippet = safeSnippet.substring(0, 400) + "...";
        }
        return new Evidence(historyId, source, lineOrOffset, safeSnippet, paramName);
    }
}
