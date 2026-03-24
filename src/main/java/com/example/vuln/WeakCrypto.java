package com.example.vuln;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Demonstrates weak cryptography vulnerabilities.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class WeakCrypto {

    // VULNERABLE: MD5 is cryptographically broken
    public static String hashPassword(String password) throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("MD5").digest(password.getBytes()));
    }

    // VULNERABLE: SHA-1 is deprecated for security use
    public static String hashToken(String token) throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest(token.getBytes()));
    }

    // VULNERABLE: DES key size is only 56 bits, easily brute-forced
    public static byte[] encryptDES(String data) throws Exception {
        SecretKey key = KeyGenerator.getInstance("DES").generateKey();
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULNERABLE: ECB mode leaks data patterns
    public static byte[] encryptECB(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULNERABLE: RC4 is a broken stream cipher
    public static byte[] encryptRC4(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }
}
