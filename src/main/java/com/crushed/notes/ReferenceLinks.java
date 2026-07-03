package com.crushed.notes;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Builds canonical reference URLs for OWASP Top 10 / CWE / WSTG ids attached to a Finding. */
public final class ReferenceLinks {

    private static final Pattern CWE_NUMBER = Pattern.compile("CWE-(\\d+)", Pattern.CASE_INSENSITIVE);

    private static final Map<String, String> OWASP_TOP10_2021_SLUGS = Map.ofEntries(
            Map.entry("A01:2021", "A01_2021-Broken_Access_Control"),
            Map.entry("A02:2021", "A02_2021-Cryptographic_Failures"),
            Map.entry("A03:2021", "A03_2021-Injection"),
            Map.entry("A04:2021", "A04_2021-Insecure_Design"),
            Map.entry("A05:2021", "A05_2021-Security_Misconfiguration"),
            Map.entry("A06:2021", "A06_2021-Vulnerable_and_Outdated_Components"),
            Map.entry("A07:2021", "A07_2021-Identification_and_Authentication_Failures"),
            Map.entry("A08:2021", "A08_2021-Software_and_Data_Integrity_Failures"),
            Map.entry("A09:2021", "A09_2021-Security_Logging_and_Monitoring_Failures"),
            Map.entry("A10:2021", "A10_2021-Server-Side_Request_Forgery_%28SSRF%29")
    );

    private static final String WSTG_GUIDE_ROOT =
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/README";

    private ReferenceLinks() {
    }

    public static String owaspTop10Url(String owaspId) {
        if (owaspId == null) return null;
        String slug = OWASP_TOP10_2021_SLUGS.get(owaspId);
        return slug == null ? null : "https://owasp.org/Top10/" + slug + "/";
    }

    public static String cweUrl(String cwe) {
        if (cwe == null) return null;
        Matcher m = CWE_NUMBER.matcher(cwe);
        return m.find() ? "https://cwe.mitre.org/data/definitions/" + m.group(1) + ".html" : null;
    }

    /** No per-test deep link (avoids embedding ~109 possibly-wrong URLs) — returns the stable guide root
     * plus the id/name as text so the user can locate the exact section themselves. */
    public static String wstgReferenceText(String wstgId, String wstgTestName) {
        if (wstgId == null) return WSTG_GUIDE_ROOT;
        String name = wstgTestName == null ? "" : " (" + wstgTestName + ")";
        return wstgId + name + " — " + WSTG_GUIDE_ROOT;
    }
}
