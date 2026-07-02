package com.crushed.analyzers.impl;

import com.crushed.analyzers.AnalysisContext;
import com.crushed.analyzers.Analyzer;
import com.crushed.core.RequestFingerprint;
import com.crushed.model.Confidence;
import com.crushed.model.Evidence;
import com.crushed.model.IssueType;
import com.crushed.model.Signal;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Passive JWT analysis: decode (no signature verification) and flag alg:none / missing exp. */
public final class JwtAnalyzer implements Analyzer {

    private static final Pattern JWT_PATTERN = Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");

    @Override
    public String name() {
        return "JwtAnalyzer";
    }

    @Override
    public List<Signal> analyze(AnalysisContext context, RequestFingerprint fingerprint) {
        List<Signal> signals = new ArrayList<>();
        String haystack = String.join("\n",
                context.requestRaw() == null ? "" : context.requestRaw(),
                context.responseRaw() == null ? "" : context.responseRaw());

        Matcher m = JWT_PATTERN.matcher(haystack);
        String endpointKey = context.host() + " " + context.method() + " " + RequestFingerprint.normalizePathTemplate(context.path());

        while (m.find()) {
            String token = m.group();
            String[] parts = token.split("\\.");
            if (parts.length < 2) continue;
            String headerJson = decodeBase64Url(parts[0]);
            String payloadJson = decodeBase64Url(parts[1]);
            if (headerJson == null) continue;

            Evidence evidence = Evidence.of(context.historyId(), Evidence.Source.RESPONSE, m.start(),
                    token.length() > 60 ? token.substring(0, 60) + "..." : token, "jwt");

            if (headerJson.toLowerCase().contains("\"alg\":\"none\"")) {
                signals.add(new Signal(IssueType.JWT_WEAKNESS, endpointKey, Confidence.FIRM,
                        "JWT header declares alg:none — server may accept unsigned tokens.", evidence));
            }
            if (payloadJson != null && !payloadJson.contains("\"exp\"")) {
                signals.add(new Signal(IssueType.JWT_WEAKNESS, endpointKey, Confidence.TENTATIVE,
                        "JWT payload has no 'exp' claim — token may never expire.", evidence));
            }
        }
        return signals;
    }

    private String decodeBase64Url(String segment) {
        try {
            return new String(Base64.getUrlDecoder().decode(pad(segment)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private String pad(String s) {
        int rem = s.length() % 4;
        if (rem == 0) return s;
        return s + "=".repeat(4 - rem);
    }
}
