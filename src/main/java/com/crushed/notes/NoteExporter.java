package com.crushed.notes;

import com.crushed.model.HostNotes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class NoteExporter {

    private final MarkdownNoteBuilder builder = new MarkdownNoteBuilder();

    public void exportMarkdown(HostNotes hostNotes, Path targetDirectory) throws IOException {
        Files.createDirectories(targetDirectory);
        Path file = targetDirectory.resolve(sanitizeFileName(hostNotes.host()) + ".md");
        Files.writeString(file, builder.render(hostNotes), StandardCharsets.UTF_8);
    }

    private String sanitizeFileName(String host) {
        return host.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
