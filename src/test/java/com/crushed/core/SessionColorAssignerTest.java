package com.crushed.core;

import burp.api.montoya.core.HighlightColor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SessionColorAssignerTest {

    @Test
    void assignsDifferentColorsToDifferentSessions() {
        SessionColorAssigner assigner = new SessionColorAssigner();

        HighlightColor colorA = assigner.colorFor("account-a-fingerprint");
        HighlightColor colorB = assigner.colorFor("account-b-fingerprint");

        assertNotEquals(colorA, colorB);
    }

    @Test
    void sameSessionAlwaysGetsSameColor() {
        SessionColorAssigner assigner = new SessionColorAssigner();

        HighlightColor first = assigner.colorFor("account-a");
        HighlightColor second = assigner.colorFor("account-a");
        HighlightColor third = assigner.colorFor("account-a");

        assertEquals(first, second);
        assertEquals(first, third);
    }

    @Test
    void tracksDistinctSessionCount() {
        SessionColorAssigner assigner = new SessionColorAssigner();
        assigner.colorFor("a");
        assigner.colorFor("b");
        assigner.colorFor("a");

        assertEquals(2, assigner.distinctSessionCount());
    }

    @Test
    void wrapsAroundPaletteAfterEightSessions() {
        SessionColorAssigner assigner = new SessionColorAssigner();
        HighlightColor first = assigner.colorFor("s0");
        for (int i = 1; i < 8; i++) {
            assigner.colorFor("s" + i);
        }
        HighlightColor ninth = assigner.colorFor("s8");

        assertEquals(first, ninth, "the 9th distinct session should wrap back to the 1st color");
    }
}
