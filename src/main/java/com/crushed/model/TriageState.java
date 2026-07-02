package com.crushed.model;

/** User-set triage decision, persisted so findings don't reappear as "new". */
public enum TriageState {
    NEW, CONFIRMED_MANUAL, FALSE_POSITIVE, IGNORED
}
