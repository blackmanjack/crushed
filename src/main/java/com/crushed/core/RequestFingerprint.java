package com.crushed.core;

import java.util.Set;

/** Result of Phase-1 classification: method, params, MIME, response class. */
public record RequestFingerprint(
        String host,
        String method,
        String pathTemplate,
        Set<String> paramNames,
        String authScheme,
        String requestMimeGuess,
        String responseMimeType,
        int responseStatusCode
) {

    public static String normalizePathTemplate(String path) {
        if (path == null || path.isEmpty()) return "/";
        String[] segments = path.split("/");
        StringBuilder sb = new StringBuilder();
        for (String seg : segments) {
            if (seg.isEmpty()) continue;
            sb.append('/');
            if (seg.matches("\\d+") || seg.matches("[0-9a-fA-F-]{8,}")) {
                sb.append("{id}");
            } else {
                sb.append(seg);
            }
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }
}
