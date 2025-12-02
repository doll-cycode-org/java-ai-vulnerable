package com.example.vuln;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class CommandInjection {
    // INTENTIONAL: demonstrates command injection via concatenation
    public static String pingHost(String host) {
        try {
            // UNSAFE: concatenating user input into OS command
            String cmd = "ping -c 1 " + host;
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
            p.waitFor();
            return sb.toString();
        } catch (Exception e) {
            return "error: " + e.getMessage();
        }
    }
}
