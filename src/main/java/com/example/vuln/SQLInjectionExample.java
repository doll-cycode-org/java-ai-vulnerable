package com.example.vuln;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Simple class that intentionally performs SQL queries using string concatenation
 * so security scanners can detect SQL injection patterns.
 *
 * This is deliberately vulnerable and should only be used in isolated test environments.
 */
public class SQLInjectionExample {

    /**
     * Executes an intentionally-vulnerable query constructed by concatenating user input.
     * Scanners should flag this as SQL injection.
     */
    public static String findUserByName(String userInput) {
        try {
            // Use H2 in-memory DB for convenience
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
            Statement st = conn.createStatement();
            // Create a simple table and seed a row (idempotent)
            st.execute("CREATE TABLE IF NOT EXISTS users(id INT AUTO_INCREMENT, username VARCHAR(255), password VARCHAR(255));");
            st.execute("MERGE INTO users KEY(username) VALUES(1, 'admin', '" + md5("password") + "')");

            // ===== INTENTIONALLY VULNERABLE QUERY =====
            // Unsafe: user input is concatenated directly into the SQL string
            String sql = "SELECT id, username FROM users WHERE username = '" + userInput + "'";
            ResultSet rs = st.executeQuery(sql);
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                sb.append("id=").append(rs.getInt("id")).append(",user=").append(rs.getString("username"));
            }
            rs.close();
            st.close();
            conn.close();
            return sb.length() == 0 ? "no results" : sb.toString();
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }

    // Helper: simple MD5 (insecure) used only for seeding
    private static String md5(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] d = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception ex) {
            return "";
        }
    }
}
