package com.example.vuln;

/**
 * Demonstrates building an LDAP query from user input without sanitization (LDAP injection).
 */
public class LDAPInjection {
    public static String buildLdapFilter(String username) {
        // UNSAFE: direct concatenation into LDAP filter
        String filter = "(uid=" + username + ")";
        // In real code this would be passed to an LDAP search; here we return the filter for scanning
        return filter;
    }
}
