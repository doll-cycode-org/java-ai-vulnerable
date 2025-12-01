package com.example;

import com.google.gson.Gson;
import static spark.Spark.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;

public class VulnApp {
    private static Properties props = new Properties();

    public static void main(String[] args) throws Exception {
        // Load properties containing 'secrets' (intentionally insecure for testing)
        props.load(VulnApp.class.getClassLoader().getResourceAsStream("application.properties"));

        port(4567);

        // Setup in-memory DB
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test;DB_CLOSE_DELAY=-1", "sa", "");
        Statement st = conn.createStatement();
        st.execute("CREATE TABLE users(username VARCHAR(255), password VARCHAR(255));");
        // seed with weak MD5 hashed password
        st.execute("INSERT INTO users(username, password) VALUES('admin', '" + md5("password") + "')");

        // Reflected XSS example
        get("/xss", (req, res) -> {
            String name = req.queryParams("name");
            if (name == null) name = "Guest";
            // UNSAFE: directly reflects input into HTML
            res.type("text/html");
            return "<html><body>Hello " + name + "</body></html>";
        });

        // SQL injection example
        get("/sql", (req, res) -> {
            String user = req.queryParams("user");
            if (user == null) user = "admin";
            // UNSAFE: concatenated SQL
            ResultSet rs = st.executeQuery("SELECT * FROM users WHERE username = '" + user + "'");
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                sb.append("user:").append(rs.getString("username")).append(" pwd:").append(rs.getString("password"));
            }
            return sb.toString();
        });

        // Login that leaks jwt secret if successful
        post("/login", (req, res) -> {
            String user = req.queryParams("username");
            String pwd = req.queryParams("password");
            if (user == null || pwd == null) return "missing";
            String hashed = md5(pwd);
            ResultSet rs = st.executeQuery("SELECT * FROM users WHERE username='" + user + "' AND password='" + hashed + "'");
            if (rs.next()) {
                // UNSAFE: returning secrets in response
                return "OK. SESSION_TOKEN=" + props.getProperty("jwt.secret") + "\n(THIS IS INTENTIONAL FOR TESTING)";
            }
            return "DENIED";
        });

        // Insecure file write (path traversal)
        post("/upload", (req, res) -> {
            String filename = req.queryParams("filename");
            String content = req.queryParams("content");
            if (filename == null || content == null) return "missing";
            File dir = new File("/tmp/vuln-uploads");
            dir.mkdirs();
            // UNSAFE: directly concatenating filename (path traversal)
            File out = new File(dir, filename);
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(content.getBytes(StandardCharsets.UTF_8));
            }
            return "written to " + out.getAbsolutePath();
        });

        // Insecure crypto (MD5)
        get("/insecure-crypto", (req, res) -> {
            String data = req.queryParams("data");
            if (data == null) return "no data";
            return md5(data);
        });

        // Endpoint that exposes configured secrets (simulate accidental leak)
        get("/secrets", (req, res) -> {
            Gson g = new Gson();
            // INTENTIONALLY returns secrets for testing scanners
            return g.toJson(props);
        });

        get("/", (req, res) -> "Vulnerable app (for scanners). See README.md");
    }

    private static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
