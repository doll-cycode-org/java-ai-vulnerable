package com.example.vuln;

import java.io.BufferedReader;
import java.io.InputStreamReader;
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

    // VULN: Command injection — user-supplied filename passed directly to Runtime.exec().
    // e.g. filename = "report.txt; rm -rf /" executes arbitrary shell commands.
    public String readFile(String filename) throws Exception {
        Process proc = Runtime.getRuntime().exec("cat /var/reports/" + filename);
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
}
