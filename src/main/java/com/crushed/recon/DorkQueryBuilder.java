package com.crushed.recon;

import java.util.List;

/** Builds the scoped dork query list for one target domain, mirroring the reference yadexloop.sh DORKS array. */
public final class DorkQueryBuilder {

    private static final List<String> TEMPLATES = List.of(
            "/api/", "graphql", "swagger", "openapi", "redoc",
            "admin", "login", "dashboard", "staging", "dev", "test", "beta", "internal",
            "_next/static", "_next/data", "chunk.js", "app.js", "main.js",
            "firebase", "s3.amazonaws.com", "config", "token", "secret", "password",
            "filetype:json", "filetype:xml", "filetype:txt", "filetype:log", "filetype:pdf"
    );

    public List<String> buildQueries(String targetDomain) {
        return TEMPLATES.stream().map(t -> "site:" + targetDomain + " " + t).toList();
    }
}
