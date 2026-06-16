package com.example.vuln;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Demonstrates hardcoded cryptographic keys and secrets.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class HardcodedKeys {

    // VULNERABLE: Hardcoded AES key embedded in source code
    private static final String AES_KEY = "MySuperSecretKey"; // UNSAFE: key in source control

    // VULNERABLE: Hardcoded JWT signing secret
    private static final String JWT_SECRET = "jwt_secret_do_not_share_1234567890ab"; // UNSAFE

    // VULNERABLE: Hardcoded API key for third-party service
    private static final String STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"; // UNSAFE

    // VULNERABLE: Hardcoded HMAC key used for signature generation
    public static String signPayload(String payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("hardcoded_hmac_key_abc123".getBytes(), "HmacSHA256")); // UNSAFE
        return Base64.getEncoder().encodeToString(mac.doFinal(payload.getBytes()));
    }

    // VULNERABLE: Hardcoded database password used in connection
    public static java.sql.Connection getConnection() throws Exception {
        return java.sql.DriverManager.getConnection("jdbc:mysql://prod-db:3306/users", "admin", "P@ssw0rd123!"); // UNSAFE
    }

    // VULNERABLE: Private key stored as a string literal
    private static final String PRIVATE_KEY_PEM =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJNB6DskRbMVBSDVMJT7a6Bqqib\n" + // UNSAFE: embedded private key
        "-----END RSA PRIVATE KEY-----";
}
