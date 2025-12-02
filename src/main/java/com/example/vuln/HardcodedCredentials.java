package com.example.vuln;

public class HardcodedCredentials {
    // INTENTIONAL: hard-coded credentials for SAST detection
    private static final String DB_URL = "jdbc:mysql://localhost:3306/vulndb";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "P@ssw0rd123!";

    public static void connect() {
        // This method is intentionally incomplete; scanners should flag the hard-coded secrets above.
        System.out.println("Connecting to " + DB_URL + " as " + DB_USER);
    }
}
