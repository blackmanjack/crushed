package com.crushed.detectors;

import com.crushed.model.Endpoint;
import com.crushed.model.Finding;

import java.util.List;

/**
 * Placeholder no-op registrations for Iterasi 2 active detectors: MassAssignmentDetector,
 * FirebaseDetector, XxeDetector, DomXssDetector, AiSessionDetector, IdorDetector, SqliDetector,
 * XssDetector, SstiDetector, SsrfDetector, RceDetector. None currently send any traffic — this
 * class exists so the ActiveDetector contract compiles and is exercised by tests before real
 * implementations land. Active mode is disabled by default in SettingsPanel.
 */
public final class NotYetImplementedDetectors {

    private NotYetImplementedDetectors() {
    }

    public static ActiveDetector noOp(String name) {
        return new ActiveDetector() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean applicable(Endpoint endpoint) {
                return false;
            }

            @Override
            public List<Finding> probe(Endpoint endpoint) {
                return List.of();
            }
        };
    }
}
