package com.crushed.model;

/** Burp-Pro-style catalog of standard issue names, descriptions, and default OWASP mapping. */
public enum IssueType {
    MASS_ASSIGNMENT("Mass assignment / identity drift", OwaspRef.MASS_ASSIGNMENT),
    FIREBASE_MISCONFIGURATION("Firebase misconfiguration", OwaspRef.FIREBASE_MISCONFIG),
    XXE("XML external entity injection", OwaspRef.XXE),
    DOM_XSS("Cross-site scripting (DOM-based)", OwaspRef.DOM_XSS),
    OPEN_REDIRECT("Open redirect", OwaspRef.OPEN_REDIRECT),
    AI_SESSION_MISCONFIGURATION("AI session misconfiguration", OwaspRef.AI_SESSION_MISCONFIG),
    IDOR_BOLA("Broken object level authorization (IDOR)", OwaspRef.IDOR_BOLA),
    SQL_INJECTION("SQL injection", OwaspRef.SQLI),
    RCE("Command / remote code execution", OwaspRef.RCE),
    REFLECTED_XSS("Cross-site scripting (reflected)", OwaspRef.XSS),
    SSTI("Server-side template injection", OwaspRef.SSTI),
    SSRF("Server-side request forgery", OwaspRef.SSRF),
    CORS_MISCONFIGURATION("CORS misconfiguration", OwaspRef.CORS_MISCONFIG),
    JWT_WEAKNESS("JWT weakness", OwaspRef.JWT_WEAKNESS),
    GRAPHQL_INTROSPECTION("GraphQL introspection enabled", OwaspRef.GRAPHQL_INTROSPECTION),
    CSRF("Cross-site request forgery", OwaspRef.CSRF),
    UNICODE_NORMALIZATION("Unicode normalization / homoglyph bypass", OwaspRef.UNICODE_NORMALIZATION),
    SENSITIVE_INFO_DISCLOSURE("Sensitive information disclosure", OwaspRef.SENSITIVE_INFO_DISCLOSURE),
    RACE_CONDITION_CANDIDATE("Business logic / race condition candidate", OwaspRef.RACE_CONDITION),
    REFLECTED_INPUT("Reflected user input", OwaspRef.REFLECTED_INPUT),
    PATH_TRAVERSAL("Path traversal", OwaspRef.PATH_TRAVERSAL),
    CRLF_INJECTION("CRLF injection / HTTP response splitting", OwaspRef.CRLF_INJECTION),
    OAUTH_MISCONFIGURATION("OAuth/OIDC misconfiguration", OwaspRef.OAUTH_MISCONFIG),
    COOKIE_MISSING_SECURE_FLAG("Cookie without Secure flag set", OwaspRef.COOKIE_MISSING_SECURE),
    COOKIE_MISSING_HTTPONLY_FLAG("Cookie without HttpOnly flag set", OwaspRef.COOKIE_MISSING_HTTPONLY),
    COOKIE_MISSING_SAMESITE("Cookie without SameSite attribute", OwaspRef.COOKIE_MISSING_SAMESITE),
    TECH_STACK_DISCLOSURE("Server/technology version disclosure", OwaspRef.TECH_STACK_DISCLOSURE),
    MISSING_HSTS("Strict-Transport-Security not enforced", OwaspRef.MISSING_HSTS),
    MISSING_X_CONTENT_TYPE_OPTIONS("X-Content-Type-Options not set", OwaspRef.MISSING_X_CONTENT_TYPE_OPTIONS),
    MISSING_CLICKJACKING_PROTECTION("Clickjacking: frameable response", OwaspRef.MISSING_CLICKJACKING_PROTECTION),
    MISSING_CSP("Content-Security-Policy not implemented", OwaspRef.MISSING_CSP),
    INSECURE_DESERIALIZATION("Insecure deserialization (Java)", OwaspRef.INSECURE_DESERIALIZATION),
    REQUEST_SMUGGLING_CANDIDATE("HTTP request smuggling candidate", OwaspRef.REQUEST_SMUGGLING),
    PROTOTYPE_POLLUTION("Server-side prototype pollution candidate", OwaspRef.PROTOTYPE_POLLUTION),
    FORBIDDEN_BYPASS("403/401 access-control bypass", OwaspRef.FORBIDDEN_BYPASS);

    private final String displayName;
    private final OwaspRef defaultOwaspRef;

    IssueType(String displayName, OwaspRef defaultOwaspRef) {
        this.displayName = displayName;
        this.defaultOwaspRef = defaultOwaspRef;
    }

    public String displayName() {
        return displayName;
    }

    public OwaspRef defaultOwaspRef() {
        return defaultOwaspRef;
    }
}
