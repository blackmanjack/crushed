package com.crushed.core;

import com.crushed.model.WstgTestCase;
import com.google.gson.Gson;

import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Loads the embedded OWASP WSTG v4.2 test catalog (full official checklist) once, from
 * {@code /wstg/wstg-checklist.json}, via Gson (already a project dependency). */
public final class WstgCatalog {

    private final List<WstgTestCase> all;

    public WstgCatalog() {
        this.all = load();
    }

    private List<WstgTestCase> load() {
        try (Reader reader = new InputStreamReader(
                getClass().getResourceAsStream("/wstg/wstg-checklist.json"), StandardCharsets.UTF_8)) {
            WstgTestCase[] entries = new Gson().fromJson(reader, WstgTestCase[].class);
            return List.of(entries);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load embedded WSTG checklist resource", e);
        }
    }

    public List<WstgTestCase> all() {
        return all;
    }
}
