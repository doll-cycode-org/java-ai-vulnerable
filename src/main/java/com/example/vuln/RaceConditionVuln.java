package com.example.vuln;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * Demonstrates race condition (TOCTOU) and thread-safety vulnerabilities.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class RaceConditionVuln {

    private static Map<String, Integer> balances = new HashMap<>(); // VULNERABLE: not thread-safe

    // VULNERABLE: TOCTOU — file existence check and use are not atomic
    public static void writeIfAbsent(String path, String content) throws Exception {
        File f = new File(path);
        if (!f.exists()) { // UNSAFE: another thread/process can create the file between check and write
            java.nio.file.Files.writeString(f.toPath(), content);
        }
    }

    // VULNERABLE: Non-atomic check-then-act on shared mutable state
    public static void transfer(String from, String to, int amount) {
        int fromBal = balances.getOrDefault(from, 0);
        if (fromBal >= amount) { // UNSAFE: balance can change between this check and the update below
            balances.put(from, fromBal - amount);
            balances.put(to, balances.getOrDefault(to, 0) + amount);
        }
    }

    // VULNERABLE: Lazy singleton without synchronization (double-checked locking broken without volatile)
    private static RaceConditionVuln instance;
    public static RaceConditionVuln getInstance() {
        if (instance == null) instance = new RaceConditionVuln(); // UNSAFE: not thread-safe
        return instance;
    }
}
