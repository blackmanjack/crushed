package com.crushed.notes;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ReferenceLinksTest {

    @Test
    void buildsOwaspTop10Url() {
        assertEquals("https://owasp.org/Top10/A03_2021-Injection/", ReferenceLinks.owaspTop10Url("A03:2021"));
    }

    @Test
    void returnsNullForUnknownOwaspId() {
        assertNull(ReferenceLinks.owaspTop10Url("A99:2021"));
    }

    @Test
    void buildsCweUrl() {
        assertEquals("https://cwe.mitre.org/data/definitions/79.html", ReferenceLinks.cweUrl("CWE-79"));
    }

    @Test
    void returnsNullForMalformedCwe() {
        assertNull(ReferenceLinks.cweUrl("not-a-cwe"));
    }

    @Test
    void wstgReferenceTextIncludesIdAndGuideRoot() {
        String text = ReferenceLinks.wstgReferenceText("WSTG-INPV-05", "Testing for SQL Injection");

        assertTrue(text.contains("WSTG-INPV-05"));
        assertTrue(text.contains("Testing for SQL Injection"));
        assertTrue(text.contains("owasp.org"));
    }
}
