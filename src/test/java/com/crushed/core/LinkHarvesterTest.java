package com.crushed.core;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LinkHarvesterTest {

    private final LinkHarvester harvester = new LinkHarvester();

    @Test
    void extractsHrefSrcAndActionLinks() {
        String body = "<a href=\"/page1\">x</a><img src=\"/img/logo.png\"><form action=\"/submit\"></form>";

        List<String> links = harvester.harvest(body);

        assertTrue(links.contains("/page1"));
        assertTrue(links.contains("/img/logo.png"));
        assertTrue(links.contains("/submit"));
    }

    @Test
    void extractsFetchAndAxiosCalls() {
        String body = "fetch('/api/users'); axios.get('/api/orders');";

        List<String> links = harvester.harvest(body);

        assertTrue(links.contains("/api/users"));
        assertTrue(links.contains("/api/orders"));
    }

    @Test
    void ignoresJavascriptAndMailtoLinks() {
        String body = "<a href=\"javascript:void(0)\">x</a><a href=\"mailto:a@b.com\">y</a>";

        List<String> links = harvester.harvest(body);

        assertTrue(links.isEmpty());
    }

    @Test
    void emptyBodyReturnsEmptyList() {
        assertTrue(harvester.harvest(null).isEmpty());
        assertTrue(harvester.harvest("").isEmpty());
    }
}
