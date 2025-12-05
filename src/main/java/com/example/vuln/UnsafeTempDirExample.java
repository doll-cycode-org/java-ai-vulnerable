package com.example.vuln;

import java.io.File;

/**
 * Shows insecure temporary directory handling and use of world-writable permissions.
 */
public class UnsafeTempDirExample {
    public static String createInsecureTempDir() {
        try {
            File dir = new File(System.getProperty("java.io.tmpdir"), "vuln-temp-dir");
            if (!dir.exists()) dir.mkdirs();
            // UNSAFE: make directory world-writable
            dir.setWritable(true, false);
            File f = new File(dir, "secret.txt");
            java.nio.file.Files.write(f.toPath(), "secret".getBytes());
            f.setReadable(true, false);
            return f.getAbsolutePath();
        } catch (Exception e) {
            return "error";
        }
    }
}
