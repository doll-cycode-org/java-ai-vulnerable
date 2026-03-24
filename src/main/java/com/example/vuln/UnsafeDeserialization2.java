package com.example.vuln;

import java.io.*;
import java.util.Base64;

/**
 * Demonstrates additional insecure deserialization patterns.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class UnsafeDeserialization2 {

    // VULNERABLE: Deserializes raw bytes from untrusted network input
    public static Object deserialize(byte[] data) throws Exception {
        return new ObjectInputStream(new ByteArrayInputStream(data)).readObject(); // UNSAFE: no class filtering
    }

    // VULNERABLE: Decodes Base64 from user input then deserializes directly
    public static Object deserializeBase64(String base64Input) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(base64Input);
        return new ObjectInputStream(new ByteArrayInputStream(bytes)).readObject(); // UNSAFE: RCE risk
    }

    // VULNERABLE: Deserializes object from a user-supplied file path
    public static Object deserializeFromFile(String filePath) throws Exception {
        return new ObjectInputStream(new FileInputStream(filePath)).readObject(); // UNSAFE: path traversal + RCE
    }

    // VULNERABLE: Custom readObject that calls user-controlled methods
    private void readObject(ObjectInputStream ois) throws Exception {
        String cmd = (String) ois.readObject();
        Runtime.getRuntime().exec(cmd); // UNSAFE: executes deserialized command
    }
}
