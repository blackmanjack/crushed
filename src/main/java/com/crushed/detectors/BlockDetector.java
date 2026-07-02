package com.crushed.detectors;

import com.crushed.identitydiff.ReplayResult;

import java.util.regex.Pattern;

/** Classifies a probe response as BLOCKED (WAF/filter), ERROR (network/5xx unrelated to a WAF), or NORMAL. */
public final class BlockDetector {

    private static final Pattern[] BLOCK_SIGNATURES = {
            Pattern.compile("(?i)access denied"),
            Pattern.compile("(?i)request rejected"),
            Pattern.compile("(?i)request unacceptable"),
            Pattern.compile("(?i)blocked by (network|web application firewall|waf)"),
            Pattern.compile("(?i)incapsula"),
            Pattern.compile("(?i)cloudflare"),
            Pattern.compile("(?i)mod_security|modsecurity"),
            Pattern.compile("(?i)checking your browser")
    };

    public enum Verdict { BLOCKED, ERROR, NORMAL }

    public Verdict classify(ReplayResult result) {
        if (result.networkError()) {
            return Verdict.ERROR;
        }
        int status = result.statusCode();
        if (status == 403 || status == 406 || status == 429) {
            return Verdict.BLOCKED;
        }
        String body = result.body() == null ? "" : result.body();
        for (Pattern p : BLOCK_SIGNATURES) {
            if (p.matcher(body).find()) {
                return Verdict.BLOCKED;
            }
        }
        if (status >= 500) {
            return Verdict.ERROR;
        }
        return Verdict.NORMAL;
    }
}
