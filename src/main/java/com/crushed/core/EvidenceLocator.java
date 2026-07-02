package com.crushed.core;

import com.crushed.model.Evidence;

/** Helpers to build precise Evidence pointers (line numbers, snippets) from raw text. */
public final class EvidenceLocator {

    private EvidenceLocator() {
    }

    public static int lineNumberOfOffset(String text, int offset) {
        if (text == null || offset <= 0) return 1;
        int line = 1;
        int limit = Math.min(offset, text.length());
        for (int i = 0; i < limit; i++) {
            if (text.charAt(i) == '\n') line++;
        }
        return line;
    }

    public static String snippetAround(String text, int offset, int radius) {
        if (text == null) return "";
        int start = Math.max(0, offset - radius);
        int end = Math.min(text.length(), offset + radius);
        return text.substring(start, end);
    }

    public static Evidence fromRequest(int historyId, String text, int offset, String param) {
        int line = lineNumberOfOffset(text, offset);
        String snippet = snippetAround(text, offset, 80);
        return Evidence.of(historyId, Evidence.Source.REQUEST, line, snippet, param);
    }

    public static Evidence fromResponse(int historyId, String text, int offset, String param) {
        int line = lineNumberOfOffset(text, offset);
        String snippet = snippetAround(text, offset, 80);
        return Evidence.of(historyId, Evidence.Source.RESPONSE, line, snippet, param);
    }

    public static Evidence fromWsFrame(int historyId, int frameIndex, String snippet) {
        return Evidence.of(historyId, Evidence.Source.WS_FRAME, frameIndex, snippet, null);
    }
}
