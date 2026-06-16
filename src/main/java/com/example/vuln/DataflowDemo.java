package com.example.vuln;

/**
 * Demonstrates a full dataflow from SOURCE to SINK for SAST testing.
 *
 * - SOURCE: `readTaintedInput()` simulates user-controlled input (e.g., HTTP param, env var)
 * - TRANSFORMS: data passes through helpers and is manipulated
 * - SINKS: `executeVulnerableQuery` concatenates the tainted value into SQL (SQLi)
 *          `exfiltrate` simulates sending tainted data to an external system
 *
 * The goal is to make a clear path for dataflow analysis tools to detect taint propagation.
 */
public class DataflowDemo {

    // SOURCE: simulate reading tainted input (e.g., from HTTP request or environment)
    public static String readTaintedInput() {
        // For demo purposes, read from system property or environment variable
        String v = System.getProperty("tainted.input");
        if (v != null && !v.isEmpty()) return v;
        v = System.getenv("TAINTED_INPUT");
        if (v != null && !v.isEmpty()) return v;
        // fallback to a literal that still should be treated as tainted in tests
        return "attacker'; DROP TABLE users; --";
    }

    // Intermediate transformation: does some harmless string operations
    public static String normalize(String s) {
        if (s == null) return null;
        // simple transform that preserves taint
        return s.trim().toLowerCase();
    }

    // Another intermediate pass-through to exercise multi-hop tracking
    public static String wrap(String s) {
        return "[wrapped]" + s + "[/wrapped]";
    }

    // SINK: vulnerable SQL execution path (calls the intentionally vulnerable method)
    public static String executeVulnerableQuery(String tainted) {
        // Here we call the earlier SQLInjectionExample which itself concatenates input into SQL
        return SQLInjectionExample.findUserByName(tainted);
    }

    // SINK: fake external exfiltration (simulates data sent to attacker-controlled endpoint)
    public static void exfiltrate(String tainted) {
        // In a real app this might POST to a remote URL; we simulate by printing
        System.out.println("EXFILTRATE:" + tainted);
    }

    // Demo main to exercise the dataflow
    public static void main(String[] args) {
        // Read tainted source
        String src = readTaintedInput();

        // Multiple transformations (multi-hop)
        String step1 = normalize(src);
        String step2 = wrap(step1);

        // Directly hit SQL sink with tainted data
        String result = executeVulnerableQuery(step2);
        System.out.println("SQL result: " + result);

        // Also exfiltrate the raw tainted input to demonstrate a different sink
        exfiltrate(src);
    }
}
