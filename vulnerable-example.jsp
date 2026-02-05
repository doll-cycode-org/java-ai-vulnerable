<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.sql.*" %>
<!DOCTYPE html>
<html>
<head>
    <title>User Search - Vulnerable Example</title>
</head>
<body>
    <h1>User Search Portal</h1>

    <%
        // Hardcoded credentials - Security violation
        String dbPassword = "MySecretP@ssw0rd123!";
        String apiKey = "sk-1234567890abcdefghijklmnop";

        // SQL Injection vulnerability - User input directly concatenated into SQL query
        String userInput = request.getParameter("username");
        String searchQuery = request.getParameter("search");

        if (userInput != null && !userInput.isEmpty()) {
            try {
                // Insecure database connection with hardcoded credentials
                String dbUrl = "jdbc:mysql://localhost:3306/userdb";
                String dbUser = "admin";
                Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);

                // SQL Injection vulnerability - no prepared statement
                Statement stmt = conn.createStatement();
                String sql = "SELECT * FROM users WHERE username = '" + userInput + "' OR email = '" + userInput + "'";
                ResultSet rs = stmt.executeQuery(sql);

                out.println("<h2>Search Results:</h2>");
                out.println("<table border='1'>");

                while (rs.next()) {
                    // XSS vulnerability - unescaped output
                    out.println("<tr>");
                    out.println("<td>" + rs.getString("username") + "</td>");
                    out.println("<td>" + rs.getString("email") + "</td>");
                    out.println("<td>" + rs.getString("role") + "</td>");
                    out.println("</tr>");
                }

                out.println("</table>");

                rs.close();
                stmt.close();
                conn.close();

            } catch (Exception e) {
                // Information disclosure - exposing stack trace
                out.println("<pre>");
                e.printStackTrace(new java.io.PrintWriter(out));
                out.println("</pre>");
            }
        }

        // XSS vulnerability - reflecting user input without sanitization
        if (searchQuery != null) {
            out.println("<p>You searched for: " + searchQuery + "</p>");
        }
    %>

    <form method="GET" action="">
        <label>Username:</label>
        <input type="text" name="username" />
        <br/><br/>
        <label>Search:</label>
        <input type="text" name="search" />
        <br/><br/>
        <input type="submit" value="Search" />
    </form>

    <!-- Debug information exposure -->
    <div style="display:none;">
        <!-- API Key: <%= apiKey %> -->
        <!-- DB Password: <%= dbPassword %> -->
    </div>

    <%
        // Command injection vulnerability
        String command = request.getParameter("cmd");
        if (command != null) {
            Runtime.getRuntime().exec(command);
        }

        // Path traversal vulnerability
        String filename = request.getParameter("file");
        if (filename != null) {
            java.io.FileInputStream fis = new java.io.FileInputStream("/var/www/files/" + filename);
        }
    %>

</body>
</html>
