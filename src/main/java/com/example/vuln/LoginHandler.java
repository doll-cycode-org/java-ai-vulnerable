package com.example.vuln;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Secure login handler for the Java app.
 *
 * Security controls applied:
 *  - Parameterised SQL queries (no string concatenation) → prevents SQL injection
 *  - Password hashing with SHA-256 + per-user salt → no plaintext or MD5 storage
 *  - Cryptographically secure session token via SecureRandom → no predictable tokens
 *  - In-memory session store with expiry → tokens are invalidated after timeout
 *  - Constant-time credential comparison → mitigates timing attacks
 *  - Generic error messages → no username enumeration
 *  - Input length validation → prevents oversized payloads
 */
public class LoginHandler {

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------
    private static final int MAX_INPUT_LENGTH = 256;
    private static final long SESSION_TTL_MS   = 30 * 60 * 1000L; // 30 minutes
    private static final int  SALT_BYTES        = 16;
    private static final int  TOKEN_BYTES        = 32;

    // -----------------------------------------------------------------------
    // Simple in-memory session store  { token -> expiry epoch ms }
    // In production, replace with a distributed cache (Redis, etc.)
    // -----------------------------------------------------------------------
    private static final ConcurrentHashMap<String, Long> SESSION_STORE = new ConcurrentHashMap<>();

    private final Connection dbConnection;

    public LoginHandler(Connection dbConnection) {
        this.dbConnection = dbConnection;
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Attempts to authenticate a user.
     *
     * @param username raw username from the request
     * @param password raw password from the request
     * @return a session token on success, or null on failure
     * @throws IllegalArgumentException if inputs are null or exceed max length
     */
    public String login(String username, String password) {
        validateInput(username, "username");
        validateInput(password, "password");

        try {
            // Fetch the stored salt + hash for this user using a parameterised query
            String[] storedCredentials = fetchStoredCredentials(username);
            if (storedCredentials == null) {
                // User not found — perform a dummy hash to avoid timing differences
                dummyHash();
                return null;
            }

            String storedSalt = storedCredentials[0];
            String storedHash = storedCredentials[1];

            // Hash the supplied password with the stored salt
            String computedHash = hashPassword(password, storedSalt);

            // Constant-time comparison to prevent timing attacks
            if (!constantTimeEquals(computedHash, storedHash)) {
                return null;
            }

            // Credentials valid — issue a session token
            return createSession();

        } catch (SQLException e) {
            // Log the exception internally; do NOT expose DB details to the caller
            System.err.println("[LoginHandler] DB error during login: " + e.getMessage());
            return null;
        }
    }

    /**
     * Validates an existing session token.
     *
     * @param token the session token to check
     * @return true if the token is valid and not expired
     */
    public boolean isSessionValid(String token) {
        if (token == null || token.isEmpty()) return false;
        Long expiry = SESSION_STORE.get(token);
        if (expiry == null) return false;
        if (System.currentTimeMillis() > expiry) {
            SESSION_STORE.remove(token);
            return false;
        }
        return true;
    }

    /**
     * Invalidates a session token (logout).
     *
     * @param token the session token to invalidate
     */
    public void logout(String token) {
        if (token != null) {
            SESSION_STORE.remove(token);
        }
    }

    /**
     * Registers a new user with a securely hashed password.
     * In production this would be a separate registration service with
     * additional controls (email verification, rate limiting, etc.).
     *
     * @param username the desired username
     * @param password the desired password (plaintext — hashed before storage)
     * @throws SQLException if the DB operation fails
     * @throws IllegalArgumentException if inputs are null or exceed max length
     */
    public void registerUser(String username, String password) throws SQLException {
        validateInput(username, "username");
        validateInput(password, "password");

        String salt = generateSalt();
        String hash = hashPassword(password, salt);

        // Parameterised INSERT — no SQL injection possible
        String sql = "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)";
        try (PreparedStatement ps = dbConnection.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, salt);
            ps.setString(3, hash);
            ps.executeUpdate();
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /** Fetches [salt, password_hash] for the given username, or null if not found. */
    private String[] fetchStoredCredentials(String username) throws SQLException {
        String sql = "SELECT salt, password_hash FROM users WHERE username = ?";
        try (PreparedStatement ps = dbConnection.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new String[]{ rs.getString("salt"), rs.getString("password_hash") };
                }
            }
        }
        return null;
    }

    /** Hashes a password with the given salt using SHA-256. */
    private static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // Prepend salt to the password before hashing
            String salted = salt + password;
            byte[] digest = md.digest(salted.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by the JVM spec — this should never happen
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /** Generates a cryptographically secure random salt. */
    private static String generateSalt() {
        byte[] saltBytes = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    /** Creates a new session token and stores it with an expiry timestamp. */
    private static String createSession() {
        byte[] tokenBytes = new byte[TOKEN_BYTES];
        new SecureRandom().nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        SESSION_STORE.put(token, System.currentTimeMillis() + SESSION_TTL_MS);
        return token;
    }

    /**
     * Constant-time string comparison — prevents timing side-channel attacks
     * where an attacker could infer how many characters matched.
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        if (aBytes.length != bBytes.length) return false;
        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result == 0;
    }

    /** Performs a dummy hash operation to equalise timing when a user is not found. */
    private static void dummyHash() {
        hashPassword("dummy", generateSalt());
    }

    /** Validates that an input is non-null and within the allowed length. */
    private static void validateInput(String value, String fieldName) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(fieldName + " must not be null or empty");
        }
        if (value.length() > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException(fieldName + " exceeds maximum allowed length");
        }
    }
}
