package com.crushed.identitydiff;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class IdentityRegistryTest {

    @Test
    void addsAndListsIdentities() {
        IdentityRegistry registry = new IdentityRegistry();
        registry.add(new Identity("low-priv", null, "session=alice"));
        registry.add(new Identity("admin", "Bearer abc", null));

        List<Identity> all = registry.all();
        assertEquals(2, all.size());
        assertEquals(2, registry.size());
    }

    @Test
    void sameLabelOverwritesPreviousIdentity() {
        IdentityRegistry registry = new IdentityRegistry();
        registry.add(new Identity("test", null, "session=old"));
        registry.add(new Identity("test", null, "session=new"));

        assertEquals(1, registry.size());
        assertEquals("session=new", registry.all().get(0).cookieHeaderValue());
    }

    @Test
    void removesByLabel() {
        IdentityRegistry registry = new IdentityRegistry();
        registry.add(new Identity("test", null, "session=x"));
        registry.remove("test");

        assertEquals(0, registry.size());
    }
}
