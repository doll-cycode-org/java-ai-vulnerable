package com.example.vuln;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * Demonstrates insecure cookie configuration vulnerabilities.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class InsecureCookies {

    // VULNERABLE: Session cookie missing HttpOnly flag (accessible via JS)
    public static void setSessionCookie(HttpServletResponse response, String sessionId) {
        Cookie cookie = new Cookie("JSESSIONID", sessionId);
        cookie.setPath("/");
        response.addCookie(cookie); // HttpOnly not set
    }

    // VULNERABLE: Auth cookie missing Secure flag (sent over HTTP)
    public static void setAuthCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("auth_token", token);
        cookie.setHttpOnly(true);
        // UNSAFE: secure flag missing — cookie sent over plain HTTP
        response.addCookie(cookie);
    }

    // VULNERABLE: Cookie with sensitive data and no flags set at all
    public static void setUserRoleCookie(HttpServletResponse response, String role) {
        response.addCookie(new Cookie("user_role", role));
    }

    // VULNERABLE: Excessively long-lived session (30 years)
    public static void setPersistentSession(HttpServletResponse response, String sessionId) {
        Cookie cookie = new Cookie("session", sessionId);
        cookie.setMaxAge(Integer.MAX_VALUE); // UNSAFE: never expires
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }
}
