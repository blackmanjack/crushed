package com.crushed.detectors;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Pure extraction logic: finds a Firebase projectId from either an init.json-style response
 *  body or a Firestore/Storage REST URL path — whichever the original finding's traffic carried. */
public final class FirebaseProjectIdExtractor {

    private static final Pattern FROM_BODY = Pattern.compile("\"projectId\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern FROM_FIRESTORE_PATH = Pattern.compile("/v1/projects/([^/]+)/databases");

    /** @param responseBody the original finding's response body (e.g. init.json), may be null
     *  @param path the original finding's request path (e.g. an existing Firestore REST call), may be null */
    public Optional<String> extract(String responseBody, String path) {
        if (responseBody != null) {
            Matcher m = FROM_BODY.matcher(responseBody);
            if (m.find()) return Optional.of(m.group(1));
        }
        if (path != null) {
            Matcher m = FROM_FIRESTORE_PATH.matcher(path);
            if (m.find()) return Optional.of(m.group(1));
        }
        return Optional.empty();
    }
}
