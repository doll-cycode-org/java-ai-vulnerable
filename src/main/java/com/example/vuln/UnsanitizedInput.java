package com.example.vuln;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UnsanitizedInput {

    // VULN: SQL injection — user input concatenated directly into query string.
    // e.g. username = "' OR '1'='1" bypasses authentication.
    public boolean login(Connection conn, String username, String password) throws Exception {
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }
}
