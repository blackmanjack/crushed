package com.crushed.model;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/** Per-host aggregation: endpoint registry + findings, thread-safe. */
public final class HostNotes {

    private final String host;
    private final ConcurrentHashMap<String, Endpoint> endpoints = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Finding> findingsByDedupeKey = new ConcurrentHashMap<>();

    public HostNotes(String host) {
        this.host = host;
    }

    public String host() {
        return host;
    }

    public Endpoint endpointFor(String key, java.util.function.Supplier<Endpoint> factory) {
        return endpoints.computeIfAbsent(key, k -> factory.get());
    }

    public Collection<Endpoint> endpoints() {
        return endpoints.values();
    }

    /** Idempotent: same dedupeKey merges rather than duplicating. */
    public void addOrMergeFinding(Finding finding) {
        findingsByDedupeKey.merge(finding.dedupeKey(), finding, (existing, incoming) -> {
            if (incoming.status() == Status.CONFIRMED) {
                existing.promoteToConfirmed();
            }
            return existing;
        });
    }

    public List<Finding> confirmedFindings() {
        return findingsByDedupeKey.values().stream()
                .filter(f -> f.status() == Status.CONFIRMED)
                .filter(f -> f.triageState() != TriageState.FALSE_POSITIVE && f.triageState() != TriageState.IGNORED)
                .toList();
    }

    public List<Finding> potentialFindings() {
        return findingsByDedupeKey.values().stream()
                .filter(f -> f.status() == Status.POTENTIAL)
                .filter(f -> f.triageState() != TriageState.FALSE_POSITIVE && f.triageState() != TriageState.IGNORED)
                .toList();
    }

    public Collection<Finding> allFindings() {
        return findingsByDedupeKey.values();
    }
}
