package com.example.vuln;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public class UnsafeFilePermissions {
    // INTENTIONAL: creates files with overly permissive permissions
    public static void writeSecrets(String filename, String data) throws Exception {
        File f = new File(filename);
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(data.getBytes(StandardCharsets.UTF_8));
        }
        // Make readable/writeable by everyone (bad practice)
        f.setReadable(true, false);
        f.setWritable(true, false);
    }
}
