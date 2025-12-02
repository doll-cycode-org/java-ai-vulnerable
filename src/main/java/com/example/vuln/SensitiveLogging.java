package com.example.vuln;

public class SensitiveLogging {
    // INTENTIONAL: logs sensitive data
    public static void login(String username, String password) {
        // UNSAFE: printing password to logs
        System.out.println("User " + username + " logged in with password: " + password);
    }
}
