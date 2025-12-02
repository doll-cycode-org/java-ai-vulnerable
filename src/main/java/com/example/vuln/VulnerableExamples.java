package com.example.vuln;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * A collection of intentionally vulnerable Java code snippets to trigger SAST rules.
 * All code is intentionally insecure and included for testing scanners only.
 */
public class VulnerableExamples {

    // INTENTIONAL: hard-coded API key (should be flagged as secret)
    private static final String API_KEY = "sk_live_FAKEAPIKEY_1234567890";

    // SQL Injection: concatenating user input into SQL
    public static String insecureSql(String userInput) {
        try {
            // Using H2 in-memory for demo; insecure concatenation below
            Connection conn = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            Statement st = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username='" + userInput + "'"; // vulnerable
            ResultSet rs = st.executeQuery(sql);
            StringBuilder sb = new StringBuilder();
            while (rs.next()) sb.append(rs.getString(1)).append(";");
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }

    // Insecure cryptography: AES in ECB mode with hard-coded key
    public static byte[] insecureCryptoECB(byte[] plaintext) {
        try {
            byte[] key = "0123456789ABCDEF".getBytes(); // weak hard-coded key
            SecretKeySpec ks = new SecretKeySpec(key, "AES");
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB is insecure
            c.init(Cipher.ENCRYPT_MODE, ks);
            return c.doFinal(plaintext);
        } catch (Exception e) {
            return null;
        }
    }

    // XXE: insecure XML parsing allowing external entities
    public static String insecureXmlParse(File xmlFile) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // INTENTIONALLY disable secure processing to allow XXE
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
            // do not disable DOCTYPE—this is intentionally insecure
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(xmlFile);
            return doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            return "error";
        }
    }

    // Insecure deserialization: reads serialized object from file without validation
    public static Object insecureDeserialize(File f) {
        try (FileInputStream fis = new FileInputStream(f);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return ois.readObject(); // unsafe: untrusted deserialization
        } catch (Exception e) {
            return null;
        }
    }

    // Command injection via Runtime.exec with user input
    public static String insecureCommand(String param) {
        try {
            String cmd = "sh -c 'ls " + param + "'"; // vulnerable concatenation
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor();
            return "done";
        } catch (Exception e) {
            return "error";
        }
    }

    // Path traversal: reading arbitrary file path from input
    public static String insecureReadFile(String path) {
        try {
            // no validation of 'path'
            byte[] data = Files.readAllBytes(Paths.get(path));
            return new String(data);
        } catch (Exception e) {
            return "error";
        }
    }

    // Predictable randomness: using java.util.Random in security context
    public static String predictableToken() {
        java.util.Random r = new java.util.Random(12345L); // predictable seed
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) sb.append(Integer.toHexString(r.nextInt(16)));
        return sb.toString();
    }

    // TOCTOU: create temp file insecurely then change permissions
    public static String insecureTempFileRace() {
        try {
            File tmp = File.createTempFile("vuln", ".tmp");
            Files.write(tmp.toPath(), "secret".getBytes());
            // set world-writable (insecure)
            tmp.setWritable(true, false);
            return tmp.getAbsolutePath();
        } catch (Exception e) {
            return "error";
        }
    }

    // Sensitive data exposure via toString/logging
    public static void logSensitive(String username, String password) {
        System.out.println("Login attempt: user=" + username + " pass=" + password); // leaks password
    }

    // Insecure reflection: instantiating class from input
    public static Object unsafeReflection(String className) {
        try {
            Class<?> cls = Class.forName(className); // unvalidated
            return cls.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            return null;
        }
    }

}
