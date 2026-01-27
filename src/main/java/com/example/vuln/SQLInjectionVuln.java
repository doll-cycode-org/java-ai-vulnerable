package com.example.vuln;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Demonstrates SQL injection vulnerabilities through unsafe query construction.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class SQLInjectionVuln {

    /**
     * Vulnerable method that concatenates user input directly into SQL query.
     * Attacker can inject SQL commands by providing input like: ' OR '1'='1
     */
    public static String getUserById(String userId) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: Direct string concatenation with user input
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            
            ResultSet rs = stmt.executeQuery(query);
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("name")).append(",");
            }
            rs.close();
            stmt.close();
            conn.close();
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Another vulnerable method using string formatting for SQL construction.
     */
    public static String searchUsers(String searchTerm) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: Using String.format with user input
            String query = String.format("SELECT * FROM users WHERE name LIKE '%s'", searchTerm);
            
            ResultSet rs = stmt.executeQuery(query);
            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("name")).append(";");
            }
            rs.close();
            stmt.close();
            conn.close();
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Vulnerable method that builds query using string concatenation in a loop.
     */
    public static String buildDynamicQuery(String... conditions) {
        String query = "SELECT * FROM products WHERE 1=1";
        
        // VULNERABLE: Concatenating user-provided conditions without sanitization
        for (String condition : conditions) {
            query += " AND " + condition;
        }
        
        return query;
    }

    /**
     * Demonstrates SQL injection with UPDATE statement.
     */
    public static void updateUserEmail(String userId, String newEmail) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: User input directly concatenated in UPDATE query
            String query = "UPDATE users SET email = '" + newEmail + "' WHERE id = '" + userId + "'";
            
            stmt.executeUpdate(query);
            stmt.close();
            conn.close();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    /**
     * Demonstrates SQL injection with DELETE statement.
     */
    public static void deleteUser(String userId) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement stmt = conn.createStatement();
            
            // VULNERABLE: Concatenated userId allows injection of DROP or DELETE ALL
            String query = "DELETE FROM users WHERE id = '" + userId + "'";
            
            stmt.executeUpdate(query);
            stmt.close();
            conn.close();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        // Example SQL injection payloads (for testing only)
        String injectionPayload = "1' OR '1'='1";
        String dropPayload = "1'; DROP TABLE users; --";
        
        System.out.println("Testing SQL Injection:");
        System.out.println(getUserById(injectionPayload));
        System.out.println(searchUsers(injectionPayload));
        System.out.println(buildDynamicQuery("status = 'active' OR '1'='1"));
    }
}
