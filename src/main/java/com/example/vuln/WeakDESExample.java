package com.example.vuln;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Demonstrates use of weak crypto (DES) with hard-coded key.
 */
public class WeakDESExample {
    public static byte[] encryptDES(byte[] data) {
        try {
            byte[] key = "12345678".getBytes(); // 8-byte DES key (weak)
            SecretKeySpec ks = new SecretKeySpec(key, "DES");
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, ks);
            return c.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }
}
