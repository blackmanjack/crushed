package com.crushed.core;

import com.crushed.model.IssueType;

/** ASVS-flavored remediation text per issue type, for use in Notes. */
public final class RemediationCatalog {

    private RemediationCatalog() {
    }

    public static String forIssueType(IssueType issueType) {
        return switch (issueType) {
            case MASS_ASSIGNMENT -> "Use explicit allow-lists for updatable fields; never bind request JSON directly to a persistence model.";
            case FIREBASE_MISCONFIGURATION -> "Set Firestore/Storage/RTDB security rules to require request.auth != null and scope reads/writes to the owning user.";
            case XXE -> "Disable DTD/external entity resolution in the XML parser (e.g. setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)).";
            case DOM_XSS -> "Avoid passing user-controlled values to location/innerHTML/eval sinks; use textContent or a sanitizer, and enforce a strict CSP.";
            case OPEN_REDIRECT -> "Validate redirect targets against an allow-list of relative paths or known hosts.";
            case AI_SESSION_MISCONFIGURATION -> "Lock session setup parameters (system prompt, tools) server-side via bidi_generate_content_setup constraints; never trust client-supplied setup frames.";
            case IDOR_BOLA -> "Enforce object-level authorization checks server-side for every request, independent of client-supplied identifiers.";
            case SQL_INJECTION -> "Use parameterized queries/prepared statements exclusively; never concatenate user input into SQL.";
            case RCE -> "Avoid passing user input to shell/process execution APIs; use safe library APIs and strict input allow-lists.";
            case REFLECTED_XSS -> "Context-aware output encoding on every reflection point; enforce CSP as defense in depth.";
            case SSTI -> "Never render user input as a template string; use a logic-less template context or explicit escaping.";
            case SSRF -> "Validate and allow-list destination hosts server-side; block requests to private/link-local ranges (e.g. 169.254.169.254).";
            case CORS_MISCONFIGURATION -> "Do not reflect arbitrary Origin with Access-Control-Allow-Credentials: true; use an explicit allow-list.";
            case JWT_WEAKNESS -> "Reject alg:none, pin the expected algorithm server-side, enforce exp, and use a strong random signing secret/key.";
            case GRAPHQL_INTROSPECTION -> "Disable introspection in production and enforce query depth/complexity limits.";
            case CSRF -> "Require a per-session anti-CSRF token on state-changing requests and set SameSite=Lax/Strict on session cookies.";
            case UNICODE_NORMALIZATION -> "Normalize input consistently (e.g. NFKC) before any security-relevant comparison, and reject mixed-script identifiers.";
            case SENSITIVE_INFO_DISCLOSURE -> "Remove hardcoded credentials/keys from client-shipped code; rotate any leaked secret immediately.";
            case RACE_CONDITION_CANDIDATE -> "Use database-level locking or idempotency keys for state-changing operations that must not be repeatable concurrently.";
            case REFLECTED_INPUT -> "Apply context-aware output encoding wherever this value is echoed, even outside HTML (JSON/XML/log sinks); treat any reflection as a potential injection point.";
            case PATH_TRAVERSAL -> "Resolve requested paths against an allow-list of filenames/IDs server-side; never concatenate user input into a filesystem path, and canonicalize+verify the result stays within the intended directory.";
            case CRLF_INJECTION -> "Strip or reject CR/LF characters from any value written into a response header; use a framework API that sets headers safely rather than raw string concatenation.";
            case OAUTH_MISCONFIGURATION -> "Require and validate a per-request `state` parameter, use the authorization code flow with PKCE instead of the implicit flow, and validate `redirect_uri` against an exact allow-list.";
        };
    }
}
