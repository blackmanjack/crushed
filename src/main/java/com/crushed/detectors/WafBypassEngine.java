package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;
import com.crushed.ui.ActivityLog;

import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Shared active-mode utility used by every detector (SSRF/SQLi/RCE/XSS/SSTI/XXE — not just XSS).
 * Sends the pure payload; if BlockDetector says BLOCKED, automatically retries with generic
 * bypass variants until one is confirmed or all variants are exhausted. On ERROR (not a block),
 * stops immediately rather than spamming a possibly-down target. Every attempt is logged.
 */
public final class WafBypassEngine {

    private final BlockDetector blockDetector;
    private final PayloadVariantGenerator variantGenerator;
    private final ActivityLog activityLog;

    public WafBypassEngine(BlockDetector blockDetector, PayloadVariantGenerator variantGenerator, ActivityLog activityLog) {
        this.blockDetector = blockDetector;
        this.variantGenerator = variantGenerator;
        this.activityLog = activityLog;
    }

    public record Outcome(boolean confirmed, String techniqueUsed, ReplayResult finalResult) {
        static Outcome none(ReplayResult last) {
            return new Outcome(false, null, last);
        }
    }

    /**
     * @param purePayload        the unobfuscated payload for this vuln class
     * @param sender             sends a payload string and returns the observed response
     * @param confirmationCheck  returns true if the response proves the vulnerability (not just "not blocked")
     */
    public Outcome sendWithAutoBypass(int historyId, String module, String purePayload,
                                       Function<String, ReplayResult> sender,
                                       Predicate<ReplayResult> confirmationCheck) {
        ReplayResult pureResult = trySend(historyId, module, "pure-payload", purePayload, sender, confirmationCheck);
        BlockDetector.Verdict pureVerdict = blockDetector.classify(pureResult);

        if (pureVerdict == BlockDetector.Verdict.NORMAL && confirmationCheck.test(pureResult)) {
            return new Outcome(true, "none (no WAF encountered)", pureResult);
        }
        if (pureVerdict == BlockDetector.Verdict.ERROR) {
            return Outcome.none(pureResult);
        }

        for (PayloadVariantGenerator.Variant variant : variantGenerator.generate(purePayload)) {
            ReplayResult result = trySend(historyId, module, variant.technique(), variant.payload(), sender, confirmationCheck);
            BlockDetector.Verdict verdict = blockDetector.classify(result);

            if (verdict == BlockDetector.Verdict.ERROR) {
                return Outcome.none(result);
            }
            if (verdict == BlockDetector.Verdict.NORMAL && confirmationCheck.test(result)) {
                activityLog.bypassed(module, historyId, "WAF bypass via " + variant.technique() + " succeeded.");
                return new Outcome(true, variant.technique(), result);
            }
        }
        return Outcome.none(pureResult);
    }

    private ReplayResult trySend(int historyId, String module, String technique, String payload,
                                  Function<String, ReplayResult> sender, Predicate<ReplayResult> confirmationCheck) {
        ReplayResult result;
        try {
            result = sender.apply(payload);
        } catch (Exception e) {
            activityLog.error(module, historyId, "Send failed for technique=" + technique + ": " + e);
            return ReplayResult.error(e.toString());
        }

        BlockDetector.Verdict verdict = blockDetector.classify(result);
        switch (verdict) {
            case BLOCKED -> activityLog.blocked(module, historyId, "Blocked (technique=" + technique + "), status=" + result.statusCode());
            case ERROR -> activityLog.error(module, historyId, "Error (technique=" + technique + "): " + result.errorMessage());
            case NORMAL -> activityLog.info(module, historyId, "Sent (technique=" + technique + "), status=" + result.statusCode());
        }
        return result;
    }
}
