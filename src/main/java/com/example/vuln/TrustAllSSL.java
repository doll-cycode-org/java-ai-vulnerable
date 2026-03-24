package com.example.vuln;

import javax.net.ssl.*;
import java.net.URL;
import java.security.cert.X509Certificate;

/**
 * Demonstrates disabled SSL/TLS certificate validation vulnerabilities.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class TrustAllSSL {

    // VULNERABLE: TrustManager that accepts any certificate (MitM risk)
    private static final TrustManager[] TRUST_ALL = new TrustManager[]{
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {} // UNSAFE: no-op
            public void checkServerTrusted(X509Certificate[] certs, String authType) {} // UNSAFE: no-op
        }
    };

    // VULNERABLE: SSLContext initialized with trust-all manager
    public static HttpsURLConnection openConnection(String url) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, TRUST_ALL, new java.security.SecureRandom());
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true); // UNSAFE: skips hostname check
        return conn;
    }

    // VULNERABLE: Globally disables hostname verification for all HTTPS connections
    public static void disableGlobalHostnameVerification() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true); // UNSAFE: global override
    }
}
