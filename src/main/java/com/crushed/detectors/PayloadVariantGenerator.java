package com.crushed.detectors;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Generic WAF/filter bypass strategies applied to a "pure" payload string, usable across
 * XSS/SQLi/SSTI/SSRF/RCE/XXE alike (not XSS-specific) per the plan's WafBypassEngine design.
 */
public final class PayloadVariantGenerator {

    public record Variant(String technique, String payload) {
    }

    public List<Variant> generate(String purePayload) {
        List<Variant> variants = new ArrayList<>();

        variants.add(new Variant("case-variation", randomizeCase(purePayload)));
        variants.add(new Variant("url-encoding", urlEncode(purePayload)));
        variants.add(new Variant("double-url-encoding", urlEncode(urlEncode(purePayload))));
        variants.add(new Variant("null-byte-insertion", insertNullByteBeforeSuspiciousChar(purePayload)));
        variants.add(new Variant("whitespace-substitution", purePayload.replace(" ", "/**/")));
        variants.add(new Variant("bracket-notation", bracketNotationIfApplicable(purePayload)));

        return variants;
    }

    private String randomizeCase(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append(i % 2 == 0 ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private String insertNullByteBeforeSuspiciousChar(String s) {
        return s.replace("<", "%00<").replace("'", "%00'");
    }

    private String bracketNotationIfApplicable(String s) {
        // e.g. "alert(" -> 'top["alert"](' — only meaningful for JS-call-shaped payloads.
        return s.replaceAll("(\\w+)\\(", "top[\"$1\"](");
    }
}
