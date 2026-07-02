package com.crushed.ui;

import com.crushed.model.Finding;
import com.crushed.model.HostNotes;
import com.crushed.model.TriageState;
import com.crushed.recon.Lead;

import java.util.List;

/**
 * Callback for UI actions that need the real MontoyaApi (send to Repeater, send live probes).
 * Kept as an interface so CrushedTab itself never depends on Montoya types directly.
 */
public interface FindingActionHandler {

    void sendToRepeater(int historyId);

    /** Runs the wired active detector for this finding's issue type, if any. Never throws. */
    List<Finding> confirmActively(Finding finding);

    /**
     * Sends a redacted summary of this host's findings to Claude for correlation/tracing.
     * Returns null if AI analysis is disabled, no API key is set, or the call failed
     * (failures are also reported to the Activity Log). Never throws.
     */
    String analyzeWithAi(HostNotes hostNotes);

    /**
     * Runs a scoped Yandex dork recon loop for the target domain. Returns unverified leads only
     * (never auto-fetched); returns an empty list if Yandex dorking is disabled. Never throws.
     */
    List<Lead> runYandexRecon(String targetDomain);

    /**
     * Replays this finding's underlying request as every registered identity and diffs the
     * response against the original. A SAME_ACCESS verdict returns a CONFIRMED BOLA/IDOR
     * finding. Returns an empty list if Active mode / Identity Diff is off or no identities are
     * registered (both reported via ActivityLog). Never throws.
     */
    List<Finding> runIdentityDiff(Finding finding);

    /**
     * Sets a finding's triage decision and persists it to the Burp project file (keyed by
     * dedupeKey), so it survives a restart and isn't re-flagged as "new" on the next scan.
     */
    void setTriageState(Finding finding, TriageState state);

    /**
     * Visits every in-scope Site Map node with no captured response yet and writes the completed
     * pair back into Burp's own Site Map, also running it through crushed's analyzer pipeline.
     * No-op (logged to ActivityLog) unless Active mode + Crawling are both enabled. Never throws.
     */
    void fillMissingSiteMapResponses();

    /**
     * Runs crushed's own bounded BFS crawler from the given seed URL, fetching in-scope pages,
     * running each through the analyzer pipeline, and following discovered links up to the
     * configured depth/request budget. No-op (logged to ActivityLog) unless Active mode +
     * Crawling are both enabled. Never throws.
     */
    void startCrawl(String seedUrl);
}
