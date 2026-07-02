package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.util.ArrayList;
import java.util.List;

/**
 * Passive homoglyph/confusable-character detection in request bodies/params, concept per
 * 0xacb.com normalization_table: mixed-script text, fullwidth ASCII, and zero-width characters
 * are flagged in security-relevant fields since they can defeat WAF keyword filters or
 * normalization-mismatched validators (account-takeover, filter bypass, traversal bypass).
 */
public final class UnicodeNormalizationAnalyzer implements Analyzer {

    private static final int[] ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0xFEFF};

    @Override
    public String name() {
        return "UnicodeNormalizationAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        String body = context.requestBody();
        if (body == null || body.isEmpty()) return List.of();

        List<Signal> signals = new ArrayList<>();
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        boolean hasCyrillicOrGreek = false;
        boolean hasFullwidth = false;
        boolean hasZeroWidth = false;
        int firstSuspiciousOffset = -1;

        for (int i = 0; i < body.length(); i++) {
            int cp = body.codePointAt(i);
            if (cp >= 0x0400 && cp <= 0x04FF || cp >= 0x0370 && cp <= 0x03FF) {
                hasCyrillicOrGreek = true;
                if (firstSuspiciousOffset < 0) firstSuspiciousOffset = i;
            }
            if (cp >= 0xFF00 && cp <= 0xFFEF) {
                hasFullwidth = true;
                if (firstSuspiciousOffset < 0) firstSuspiciousOffset = i;
            }
            for (int zw : ZERO_WIDTH) {
                if (cp == zw) {
                    hasZeroWidth = true;
                    if (firstSuspiciousOffset < 0) firstSuspiciousOffset = i;
                }
            }
        }

        boolean hasAscii = body.chars().anyMatch(c -> c < 128 && Character.isLetter(c));

        if ((hasCyrillicOrGreek && hasAscii) || hasFullwidth || hasZeroWidth) {
            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.REQUEST, Math.max(firstSuspiciousOffset, 0),
                    "mixed-script/confusable/zero-width character detected in request body", null);
            signals.add(new Signal(
                    IssueType.UNICODE_NORMALIZATION,
                    endpointKey,
                    Confidence.TENTATIVE,
                    "Body contains confusable/mixed-script or zero-width characters; could indicate a homoglyph " +
                            "bypass attempt or a normalization mismatch between validation and storage/display.",
                    evidence
            ));
        }
        return signals;
    }
}
