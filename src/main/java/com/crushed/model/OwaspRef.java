package com.crushed.model;

/** Single source of truth for OWASP / WSTG / CWE references attached to a Finding. */
public record OwaspRef(String owaspTop10, String owaspApiTop10, String wstgId, String cwe) {

    public static final OwaspRef MASS_ASSIGNMENT =
            new OwaspRef("A04:2021", "API3:2023", "WSTG-BUSL-01", "CWE-915");
    public static final OwaspRef FIREBASE_MISCONFIG =
            new OwaspRef("A05:2021", null, "WSTG-CONF-01", "CWE-1188");
    public static final OwaspRef XXE =
            new OwaspRef("A03:2021", null, "WSTG-INPV-07", "CWE-611");
    public static final OwaspRef DOM_XSS =
            new OwaspRef("A03:2021", null, "WSTG-CLNT-01", "CWE-79");
    public static final OwaspRef OPEN_REDIRECT =
            new OwaspRef("A03:2021", null, "WSTG-CLNT-04", "CWE-601");
    public static final OwaspRef AI_SESSION_MISCONFIG =
            new OwaspRef("A05:2021", "API8:2023", "WSTG-CONF-01", "CWE-16");
    public static final OwaspRef IDOR_BOLA =
            new OwaspRef("A01:2021", "API1:2023", "WSTG-ATHZ-04", "CWE-639");
    public static final OwaspRef SQLI =
            new OwaspRef("A03:2021", null, "WSTG-INPV-05", "CWE-89");
    public static final OwaspRef RCE =
            new OwaspRef("A03:2021", null, "WSTG-INPV-12", "CWE-78");
    public static final OwaspRef XSS =
            new OwaspRef("A03:2021", null, "WSTG-INPV-01", "CWE-79");
    public static final OwaspRef SSTI =
            new OwaspRef("A03:2021", null, "WSTG-INPV-18", "CWE-1336");
    public static final OwaspRef SSRF =
            new OwaspRef("A01:2021", null, "WSTG-INPV-19", "CWE-918");
    public static final OwaspRef CORS_MISCONFIG =
            new OwaspRef("A05:2021", null, "WSTG-CONF-07", "CWE-942");
    public static final OwaspRef JWT_WEAKNESS =
            new OwaspRef("A07:2021", "API2:2023", "WSTG-ATHN-07", "CWE-347");
    public static final OwaspRef GRAPHQL_INTROSPECTION =
            new OwaspRef("A05:2021", "API9:2023", "WSTG-CONF-01", "CWE-200");
    public static final OwaspRef CSRF =
            new OwaspRef("A01:2021", null, "WSTG-SESS-05", "CWE-352");
    public static final OwaspRef UNICODE_NORMALIZATION =
            new OwaspRef("A03:2021", null, "WSTG-INPV-16", "CWE-176");
    public static final OwaspRef SENSITIVE_INFO_DISCLOSURE =
            new OwaspRef("A05:2021", null, "WSTG-CONF-01", "CWE-200");
    public static final OwaspRef RACE_CONDITION =
            new OwaspRef("A04:2021", null, "WSTG-BUSL-07", "CWE-362");
    public static final OwaspRef REFLECTED_INPUT =
            new OwaspRef("A03:2021", null, "WSTG-INPV-01", "CWE-20");
    public static final OwaspRef PATH_TRAVERSAL =
            new OwaspRef("A01:2021", null, "WSTG-ATHZ-01", "CWE-22");
    public static final OwaspRef CRLF_INJECTION =
            new OwaspRef("A03:2021", null, "WSTG-INPV-15", "CWE-93");
    public static final OwaspRef OAUTH_MISCONFIG =
            new OwaspRef("A07:2021", "API2:2023", "WSTG-ATHN-01", "CWE-346");
    public static final OwaspRef COOKIE_MISSING_SECURE =
            new OwaspRef("A05:2021", null, "WSTG-SESS-02", "CWE-614");
    public static final OwaspRef COOKIE_MISSING_HTTPONLY =
            new OwaspRef("A05:2021", null, "WSTG-SESS-02", "CWE-1004");
    public static final OwaspRef COOKIE_MISSING_SAMESITE =
            new OwaspRef("A05:2021", null, "WSTG-SESS-02", "CWE-352");
    public static final OwaspRef TECH_STACK_DISCLOSURE =
            new OwaspRef("A05:2021", null, "WSTG-INFO-02", "CWE-200");
    public static final OwaspRef MISSING_HSTS =
            new OwaspRef("A05:2021", null, "WSTG-CONF-07", "CWE-319");
    public static final OwaspRef MISSING_X_CONTENT_TYPE_OPTIONS =
            new OwaspRef("A05:2021", null, "WSTG-CONF-07", "CWE-693");
    public static final OwaspRef MISSING_CLICKJACKING_PROTECTION =
            new OwaspRef("A05:2021", null, "WSTG-CLNT-09", "CWE-1021");
    public static final OwaspRef MISSING_CSP =
            new OwaspRef("A05:2021", null, "WSTG-CONF-07", "CWE-693");
    public static final OwaspRef INSECURE_DESERIALIZATION =
            new OwaspRef("A08:2021", null, "WSTG-BUSL-03", "CWE-502");
    public static final OwaspRef REQUEST_SMUGGLING =
            new OwaspRef("A05:2021", null, "WSTG-INPV-15", "CWE-444");
    public static final OwaspRef PROTOTYPE_POLLUTION =
            new OwaspRef("A03:2021", null, "WSTG-INPV-11", "CWE-1321");
    public static final OwaspRef FORBIDDEN_BYPASS =
            new OwaspRef("A01:2021", "API1:2023", "WSTG-ATHZ-02", "CWE-284");
}
