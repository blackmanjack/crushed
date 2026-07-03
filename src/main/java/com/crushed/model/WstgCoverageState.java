package com.crushed.model;

/** User-set manual WSTG test-case status, persisted so it doesn't reset on restart. */
public enum WstgCoverageState {
    NOT_TESTED, TESTED_NO_ISSUES, TESTED_ISSUES_FOUND, NOT_APPLICABLE
}
