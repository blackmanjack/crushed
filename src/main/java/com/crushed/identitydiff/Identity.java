package com.crushed.identitydiff;

/** A labeled credential set the user registers for replay-based authz testing (Autorize-style). */
public record Identity(String label, String authorizationHeaderValue, String cookieHeaderValue) {

    public boolean hasBearer() {
        return authorizationHeaderValue != null && !authorizationHeaderValue.isBlank();
    }

    public boolean hasCookie() {
        return cookieHeaderValue != null && !cookieHeaderValue.isBlank();
    }
}
