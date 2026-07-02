package com.crushed.identitydiff;

import java.util.Map;

/** Response captured from a replay attempt (real or simulated), independent of Montoya types. */
public record ReplayResult(int statusCode, String body, boolean networkError, String errorMessage, Map<String, String> headers) {

    public static ReplayResult ok(int statusCode, String body) {
        return new ReplayResult(statusCode, body == null ? "" : body, false, null, Map.of());
    }

    public static ReplayResult ok(int statusCode, String body, Map<String, String> headers) {
        return new ReplayResult(statusCode, body == null ? "" : body, false, null, headers == null ? Map.of() : headers);
    }

    public static ReplayResult error(String message) {
        return new ReplayResult(0, "", true, message, Map.of());
    }
}
