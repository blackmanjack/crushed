package com.crushed.ai;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RedactorTest {

    private final Redactor redactor = new Redactor();

    @Test
    void masksJwt() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
        String result = redactor.redact("token=" + jwt);
        assertFalse(result.contains(jwt));
        assertTrue(result.contains("[REDACTED]"));
    }

    @Test
    void masksAwsKey() {
        String result = redactor.redact("aws_key: AKIAABCDEFGHIJKLMNOP");
        assertFalse(result.contains("AKIAABCDEFGHIJKLMNOP"));
    }

    @Test
    void masksCookieHeader() {
        String result = redactor.redact("Cookie: session=abc123; other=xyz\nNext-Line: ok");
        assertFalse(result.contains("session=abc123"));
        assertTrue(result.contains("Next-Line: ok"));
    }

    @Test
    void leavesOrdinaryTextUntouched() {
        String result = redactor.redact("This is a normal sentence with no secrets.");
        assertEquals("This is a normal sentence with no secrets.", result);
    }
}
