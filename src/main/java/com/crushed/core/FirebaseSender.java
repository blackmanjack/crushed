package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.ui.ActivityLog;

import java.util.function.BooleanSupplier;

/**
 * Sends an unauthenticated GET to the public Firestore REST API for a given project — this
 * targets a fixed Google-owned host (firestore.googleapis.com), not the original finding's
 * host, since Firebase's REST surface is project-scoped rather than app-hostname-scoped.
 * Gated by activeModeEnabled only (no ScopeGate check, since the target host is never the
 * app's own scope) — Active mode being on is the user's explicit authorization to probe.
 */
public final class FirebaseSender {

    private static final String FIRESTORE_HOST = "firestore.googleapis.com";

    private final MontoyaApi api;
    private final BooleanSupplier activeModeEnabled;
    private final ActivityLog activityLog;

    public FirebaseSender(MontoyaApi api, BooleanSupplier activeModeEnabled, ActivityLog activityLog) {
        this.api = api;
        this.activeModeEnabled = activeModeEnabled;
        this.activityLog = activityLog;
    }

    public ReplayResult probeFirestore(String projectId) {
        if (!activeModeEnabled.getAsBoolean()) {
            return ReplayResult.error("Active mode is disabled; refusing to send.");
        }
        try {
            HttpService service = HttpService.httpService(FIRESTORE_HOST, 443, true);
            String path = "/v1/projects/" + projectId + "/databases/(default)/documents?pageSize=1";
            HttpRequest request = HttpRequest.httpRequest(service, "GET " + path + " HTTP/1.1\r\nHost: " + FIRESTORE_HOST + "\r\n\r\n");
            HttpRequestResponse result = api.http().sendRequest(request);
            if (result.response() == null) {
                return ReplayResult.error("No response received from Firestore.");
            }
            return ReplayResult.ok(result.response().statusCode(), result.response().bodyToString());
        } catch (Exception e) {
            activityLog.error("FirebaseSender", -1, "Firestore probe failed for project '" + projectId + "': " + e);
            return ReplayResult.error(e.toString());
        }
    }
}
