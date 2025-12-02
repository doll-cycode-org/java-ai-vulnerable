package com.example.vuln;

/**
 * Open redirect example: returns a redirect target based on user input without validation.
 */
public class OpenRedirectExample {
    public static String getRedirectLocation(String target) {
        // UNSAFE: no validation/whitelisting of redirect target
        return target;
    }
}
