package com.crushed.core;

import com.crushed.model.Endpoint;
import com.crushed.model.Finding;
import com.crushed.model.HostNotes;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Persistent, ever-growing registry of hosts -> endpoints. Idempotent updates. */
public final class EndpointRegistry {

    private final ConcurrentHashMap<String, HostNotes> hostsByName = new ConcurrentHashMap<>();

    public HostNotes hostNotesFor(String host) {
        return hostsByName.computeIfAbsent(host, HostNotes::new);
    }

    public Endpoint recordSighting(String host, String method, String pathTemplate, int historyId,
                                    Set<String> paramNames, String authScheme, String mimeType) {
        HostNotes hostNotes = hostNotesFor(host);
        String key = host + " " + method + " " + pathTemplate;
        Endpoint endpoint = hostNotes.endpointFor(key, () -> new Endpoint(host, method, pathTemplate));
        endpoint.recordSighting(historyId, paramNames, authScheme, mimeType);
        return endpoint;
    }

    public Iterable<HostNotes> allHosts() {
        return hostsByName.values();
    }

    public int hostCount() {
        return hostsByName.size();
    }

    /** Flat-maps every HostNotes.allFindings() across every registered host — needed for
     * global views (e.g. WSTG-coverage) that aren't scoped to a single selected host. */
    public List<Finding> allFindingsAcrossHosts() {
        List<Finding> all = new ArrayList<>();
        for (HostNotes hostNotes : hostsByName.values()) {
            all.addAll(hostNotes.allFindings());
        }
        return all;
    }
}
