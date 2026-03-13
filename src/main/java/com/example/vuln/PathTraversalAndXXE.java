package com.example.vuln;

import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Demonstrates path traversal, XXE injection, and Zip Slip vulnerabilities.
 * FOR EDUCATIONAL/TESTING PURPOSES ONLY — do not use in production.
 */
public class PathTraversalAndXXE {

    private static final String BASE_DIR = "/var/app/files/";

    // VULN: Path traversal — user-controlled filename not sanitized.
    // Attacker can pass "../../etc/passwd" to read arbitrary files.
    public String readUserFile(String filename) throws IOException {
        String path = BASE_DIR + filename;
        return new String(Files.readAllBytes(Paths.get(path)));
    }

    // VULN: XXE injection — DocumentBuilderFactory created with external
    // entity expansion enabled (the default). Attacker-supplied XML can
    // read local files or trigger SSRF via external DTD.
    public String parseXml(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));
        return doc.getDocumentElement().getTextContent();
    }

    // VULN: Zip Slip — entry names from a zip archive are not validated before
    // writing, allowing a crafted archive to overwrite arbitrary files outside
    // the destination directory (e.g. "../../.ssh/authorized_keys").
    public void extractZip(InputStream zipStream, String destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(zipStream)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // No check that entry.getName() stays within destDir
                File outFile = new File(destDir, entry.getName());
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    byte[] buf = new byte[4096];
                    int len;
                    while ((len = zis.read(buf)) > 0) {
                        fos.write(buf, 0, len);
                    }
                }
            }
        }
    }

    // VULN: Path traversal via HTTP parameter written directly to disk.
    // E.g. request parameter "report=../../../../etc/crontab" overwrites crontab.
    public void saveReport(String reportName, String content) throws IOException {
        String filePath = "/var/reports/" + reportName + ".txt";
        Files.write(Paths.get(filePath), content.getBytes());
    }
}
