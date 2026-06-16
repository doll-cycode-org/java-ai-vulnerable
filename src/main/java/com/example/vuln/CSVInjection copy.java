package com.example.vuln;

import java.io.FileWriter;

/**
 * Demonstrates CSV injection: writing untrusted values that can be interpreted by spreadsheet formulas.
 */
public class CSVInjection {
    public static void writeRow(String filename, String[] values) {
        try (FileWriter fw = new FileWriter(filename, true)) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < values.length; i++) {
                String v = values[i];
                // UNSAFE: writing values directly; spreadsheet apps may treat leading '=' as formula
                sb.append(v);
                if (i < values.length - 1) sb.append(',');
            }
            sb.append('\n');
            fw.write(sb.toString());
        } catch (Exception e) {
            // ignore
        }
    }
}
