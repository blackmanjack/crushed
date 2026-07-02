package com.crushed.core;

import burp.api.montoya.core.HighlightColor;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Assigns a stable HighlightColor to each distinct session fingerprint (first-seen order),
 * so every request from "Account A" always lights up the same color in Burp's HTTP history,
 * and "Account B" gets a different one. Cycles through an 8-color palette; if more than 8
 * distinct sessions are seen, colors repeat (documented limitation, not a bug — 8 concurrent
 * test accounts is already an unusual scenario).
 */
public final class SessionColorAssigner {

    private static final HighlightColor[] PALETTE = {
            HighlightColor.RED, HighlightColor.ORANGE, HighlightColor.YELLOW, HighlightColor.GREEN,
            HighlightColor.CYAN, HighlightColor.BLUE, HighlightColor.PINK, HighlightColor.MAGENTA
    };

    private final Map<String, HighlightColor> assigned = new ConcurrentHashMap<>();
    private final AtomicInteger nextIndex = new AtomicInteger(0);

    public HighlightColor colorFor(String sessionFingerprint) {
        return assigned.computeIfAbsent(sessionFingerprint, k -> PALETTE[nextIndex.getAndIncrement() % PALETTE.length]);
    }

    public int distinctSessionCount() {
        return assigned.size();
    }
}
