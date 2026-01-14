package com.example.vuln;

/**
 * This file intentionally contains hard-coded secrets for testing secret scanning tools.
 * All values are fake and should not be used in production.
 */
public class ExposedSecrets {

    // Fake API keys
    public static final String GITHUB_TOKEN = "ghp_FAKE_GITHUB_TOKEN_1234567890";
    public static final String AWS_ACCESS_KEY_ID = "AKIAFAKEACCESSKEYEXAMPLE";
    public static final String AWS_SECRET_ACCESS_KEY = "FAKE_AWS_SECRET_KEY_1234567890";
    public static final String STRIPE_SECRET_KEY = "sk_live_FAKE_STRIPE_KEY_abcdef123456";

    // Fake database credentials
    public static final String DB_PASSWORD = "supersecretpassword123";

    // Fake private key (PEM format)
    public static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "FAKE_PRIVATE_KEY_LINE_1\n" +
            "FAKE_PRIVATE_KEY_LINE_2\n" +
            "-----END PRIVATE KEY-----";

    // Method to "use" the secrets (for testing dataflow)
    public static void printSecrets() {
        System.out.println("GitHub Token: " + GITHUB_TOKEN);
        System.out.println("AWS Key: " + AWS_ACCESS_KEY_ID);
        System.out.println("Stripe Key: " + STRIPE_SECRET_KEY);
        System.out.println("DB Password: " + DB_PASSWORD);
        System.out.println("Private Key: " + PRIVATE_KEY);
    }
}