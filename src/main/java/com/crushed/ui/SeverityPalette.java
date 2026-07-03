package com.crushed.ui;

import com.crushed.model.Severity;
import com.crushed.model.Status;

import java.awt.Color;

/** Burp-Pro-convention severity/status colors: HIGH=red, MEDIUM=orange, LOW=yellow/gold, INFO=blue-gray. */
public final class SeverityPalette {

    private static final Color HIGH = new Color(0xC0, 0x39, 0x2B);
    private static final Color MEDIUM = new Color(0xE6, 0x7E, 0x22);
    private static final Color LOW = new Color(0xC9, 0xA0, 0x0F);
    private static final Color INFO = new Color(0x5B, 0x7A, 0x9A);
    private static final Color CONFIRMED = new Color(0x1E, 0x7A, 0x34);

    private SeverityPalette() {
    }

    public static Color forSeverity(Severity severity) {
        return switch (severity) {
            case HIGH -> HIGH;
            case MEDIUM -> MEDIUM;
            case LOW -> LOW;
            case INFO -> INFO;
        };
    }

    public static Color forStatus(Status status) {
        return status == Status.CONFIRMED ? CONFIRMED : Color.DARK_GRAY;
    }
}
