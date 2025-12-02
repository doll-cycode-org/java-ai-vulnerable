package com.example.vuln;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Simple SSRF-like example: fetches a URL supplied by caller without validation.
 */
public class SSRFExample {
    public static String fetchUrl(String urlStr) {
        try {
            // UNSAFE: no validation of the URL (could be internal addresses)
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) sb.append(line).append('\n');
            in.close();
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }
}
