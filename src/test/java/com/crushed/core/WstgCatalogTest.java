package com.crushed.core;

import com.crushed.model.WstgTestCase;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class WstgCatalogTest {

    @Test
    void loadsWithoutErrorAndHasSaneSize() {
        List<WstgTestCase> all = new WstgCatalog().all();

        assertTrue(all.size() > 50, "expected the full WSTG catalog, got " + all.size());
    }

    @Test
    void everyEntryHasNonBlankFields() {
        for (WstgTestCase test : new WstgCatalog().all()) {
            assertNotNull(test.id());
            assertFalse(test.id().isBlank());
            assertNotNull(test.category());
            assertFalse(test.category().isBlank());
            assertNotNull(test.name());
            assertFalse(test.name().isBlank());
        }
    }

    @Test
    void idsAreUnique() {
        List<WstgTestCase> all = new WstgCatalog().all();
        Set<String> ids = all.stream().map(WstgTestCase::id).collect(java.util.stream.Collectors.toSet());

        assertEquals(all.size(), ids.size(), "expected every WSTG id to be unique");
    }

    @Test
    void coversAllTwelveCategories() {
        Set<String> categories = new WstgCatalog().all().stream()
                .map(WstgTestCase::category)
                .collect(java.util.stream.Collectors.toSet());

        assertEquals(12, categories.size(), "expected all 12 WSTG v4.2 categories");
    }
}
