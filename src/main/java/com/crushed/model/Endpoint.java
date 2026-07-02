package com.crushed.model;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

/**
 * Detailed, mutable-via-merge record of one endpoint (host+method+path-template).
 * Thread-safe: fields are concurrent collections, merge() is called from proxy handler threads.
 */
public final class Endpoint {

    private final String host;
    private final String method;
    private final String pathTemplate;
    private final Set<String> paramNames = ConcurrentHashMap.newKeySet();
    private final Set<String> authSchemesSeen = ConcurrentHashMap.newKeySet();
    private final Set<String> mimeTypesSeen = ConcurrentHashMap.newKeySet();
    private final Set<Integer> historyIds = new ConcurrentSkipListSet<>();
    private volatile long firstSeenEpochMs;
    private volatile long lastSeenEpochMs;

    public Endpoint(String host, String method, String pathTemplate) {
        this.host = host;
        this.method = method;
        this.pathTemplate = pathTemplate;
        long now = System.currentTimeMillis();
        this.firstSeenEpochMs = now;
        this.lastSeenEpochMs = now;
    }

    public String key() {
        return host + " " + method + " " + pathTemplate;
    }

    public void recordSighting(int historyId, Set<String> params, String authScheme, String mimeType) {
        historyIds.add(historyId);
        if (params != null) paramNames.addAll(params);
        if (authScheme != null) authSchemesSeen.add(authScheme);
        if (mimeType != null) mimeTypesSeen.add(mimeType);
        lastSeenEpochMs = System.currentTimeMillis();
    }

    public String host() { return host; }
    public String method() { return method; }
    public String pathTemplate() { return pathTemplate; }
    public Set<String> paramNames() { return paramNames; }
    public Set<String> authSchemesSeen() { return authSchemesSeen; }
    public Set<String> mimeTypesSeen() { return mimeTypesSeen; }
    public Set<Integer> historyIds() { return historyIds; }
    public long firstSeenEpochMs() { return firstSeenEpochMs; }
    public long lastSeenEpochMs() { return lastSeenEpochMs; }
}
