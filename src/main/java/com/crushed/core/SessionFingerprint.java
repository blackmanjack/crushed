package com.crushed.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * Identifies which logged-in session/account a request belongs to, without ever storing the
 * raw cookie/token. Shared by SessionDiffAnalyzer (passive BOLA detection) and the HTTP-history
 * highlight-by-account feature — both need the same notion of "which account is this".
 */
public final class SessionFingerprint {

    private SessionFingerprint() {
    }

    /** Returns null if the request carries no Cookie/Authorization header to fingerprint. */
    public static String extract(Map<String, String> requestHeaders) {
        if (requestHeaders == null) return null;
        String cookie = requestHeaders.get("Cookie");
        String auth = requestHeaders.get("Authorization");
        String raw = cookie != null ? cookie : auth;
        if (raw == null || raw.isBlank()) return null;
        return shortHash(raw);
    }

    private static String shortHash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "unhashable";
        }
    }
}
