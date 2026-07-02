package com.crushed.core;

import burp.api.montoya.MontoyaApi;

/** Single point of decision for in/out of Burp's configured scope. */
public final class ScopeGate {

    private final MontoyaApi api;

    public ScopeGate(MontoyaApi api) {
        this.api = api;
    }

    public boolean isInScope(String url) {
        if (url == null || url.isBlank()) return false;
        try {
            return api.scope().isInScope(url);
        } catch (Exception e) {
            api.logging().logToError("ScopeGate.isInScope failed for url=" + url + ": " + e);
            return false;
        }
    }
}
