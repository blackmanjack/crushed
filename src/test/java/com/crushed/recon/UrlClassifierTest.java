package com.crushed.recon;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UrlClassifierTest {

    private final UrlClassifier classifier = new UrlClassifier();

    @Test
    void classifiesApiEndpoint() {
        assertEquals(Lead.Bucket.API, classifier.classify("https://example.com/api/v1/users"));
    }

    @Test
    void classifiesJavaScriptAsset() {
        assertEquals(Lead.Bucket.JAVASCRIPT, classifier.classify("https://example.com/_next/static/chunk.js"));
    }

    @Test
    void classifiesAdminPage() {
        assertEquals(Lead.Bucket.AUTH_ADMIN, classifier.classify("https://example.com/admin/login"));
    }

    @Test
    void classifiesEnvironmentPath() {
        assertEquals(Lead.Bucket.ENVIRONMENTS, classifier.classify("https://staging.example.com/"));
    }

    @Test
    void classifiesJsonFile() {
        assertEquals(Lead.Bucket.FILES, classifier.classify("https://example.com/config.json"));
    }

    @Test
    void classifiesDocument() {
        assertEquals(Lead.Bucket.DOCUMENTS, classifier.classify("https://example.com/report.pdf"));
    }

    @Test
    void classifiesUnmatchedAsOther() {
        assertEquals(Lead.Bucket.OTHER, classifier.classify("https://example.com/about-us"));
    }
}
