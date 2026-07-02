package com.crushed.identitydiff;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;

/** Thread-safe store of user-registered identities for the Identity Diff Engine. */
public final class IdentityRegistry {

    private final Map<String, Identity> byLabel = new ConcurrentSkipListMap<>();

    public void add(Identity identity) {
        byLabel.put(identity.label(), identity);
    }

    public void remove(String label) {
        byLabel.remove(label);
    }

    public List<Identity> all() {
        return List.copyOf(byLabel.values());
    }

    public int size() {
        return byLabel.size();
    }
}
