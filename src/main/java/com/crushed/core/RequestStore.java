package com.crushed.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Mints and holds the stable "Req #id" that Notes/Evidence/UI refer back to. Montoya exposes no
 * durable numeric id on HttpRequestResponse, so crushed mints its own monotonically increasing
 * counter and keeps the live objects here — this is what makes "jump to request" and active
 * replay (rebuilding a ReplayableRequest from the original) possible after the fact.
 */
public final class RequestStore {

    public record Stored(HttpRequest request, HttpResponse response) {
    }

    private final AtomicInteger nextId = new AtomicInteger(1);
    private final ConcurrentHashMap<Integer, Stored> byId = new ConcurrentHashMap<>();

    /** Mints a new id for this request/response pair and stores it. */
    public int record(HttpRequest request, HttpResponse response) {
        int id = nextId.getAndIncrement();
        byId.put(id, new Stored(request, response));
        return id;
    }

    public Stored get(int historyId) {
        return byId.get(historyId);
    }

    public int size() {
        return byId.size();
    }
}
