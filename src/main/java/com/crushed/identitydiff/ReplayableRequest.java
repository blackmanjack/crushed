package com.crushed.identitydiff;

import java.util.Map;

/** Plain-data description of a request to replay, decoupled from Montoya types for testability. */
public record ReplayableRequest(
        int originalHistoryId,
        String host,
        String method,
        String path,
        Map<String, String> headers,
        String body
) {
}
