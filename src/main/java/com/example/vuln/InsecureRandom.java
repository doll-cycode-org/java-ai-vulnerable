package com.example.vuln;

import java.util.Random;

public class InsecureRandom {
    // INTENTIONAL: using java.util.Random for security-sensitive token generation
    public static String generateToken() {
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append(Integer.toHexString(r.nextInt(16)));
        }
        return sb.toString();
    }
}
