package com.crushed.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.crushed.identitydiff.ReplayResult;
import com.crushed.identitydiff.ReplayableRequest;
import com.crushed.identitydiff.RequestSender;
import com.crushed.ui.ActivityLog;

import java.util.function.BooleanSupplier;

/**
 * Real RequestSender backed by montoyaApi.http().sendRequest(). Every call is gated by
 * activeModeEnabled AND ScopeGate — belt-and-suspenders, since callers should already check
 * both before invoking any Iterasi-2 module.
 */
public final class MontoyaRequestSender implements RequestSender {

    private final MontoyaApi api;
    private final ScopeGate scopeGate;
    private final BooleanSupplier activeModeEnabled;
    private final ActivityLog activityLog;

    public MontoyaRequestSender(MontoyaApi api, ScopeGate scopeGate, BooleanSupplier activeModeEnabled, ActivityLog activityLog) {
        this.api = api;
        this.scopeGate = scopeGate;
        this.activeModeEnabled = activeModeEnabled;
        this.activityLog = activityLog;
    }

    @Override
    public ReplayResult send(ReplayableRequest request) {
        if (!activeModeEnabled.getAsBoolean()) {
            return ReplayResult.error("Active mode is disabled; refusing to send.");
        }
        String url = "https://" + request.host() + request.path();
        if (!scopeGate.isInScope(url)) {
            return ReplayResult.error("Host is out of scope; refusing to send: " + request.host());
        }

        try {
            HttpService service = HttpService.httpService(request.host());
            HttpRequest httpRequest = HttpRequest.httpRequest(service, request.method() + " " + request.path() + " HTTP/1.1\r\n\r\n");
            for (var header : request.headers().entrySet()) {
                httpRequest = httpRequest.withAddedHeader(header.getKey(), header.getValue());
            }
            if (request.body() != null && !request.body().isEmpty()) {
                httpRequest = httpRequest.withBody(request.body());
            }

            HttpRequestResponse result = api.http().sendRequest(httpRequest);
            if (result.response() == null) {
                return ReplayResult.error("No response received.");
            }
            return ReplayResult.ok(result.response().statusCode(), result.response().bodyToString());
        } catch (Exception e) {
            activityLog.error("MontoyaRequestSender", request.originalHistoryId(), "Send failed: " + e);
            return ReplayResult.error(e.toString());
        }
    }
}
