package com.example.vuln;

import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.InputStream;
import java.io.StringReader;
import org.xml.sax.InputSource;

/**
 * Demonstrates XML External Entity (XXE) injection vulnerabilities.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class XXEInjection {

    // VULNERABLE: DocumentBuilderFactory with external entities enabled (default)
    public static Document parseXml(InputStream xmlStream) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(xmlStream);
    }

    // VULNERABLE: Parses user-supplied XML string without disabling XXE
    public static Document parseXmlString(String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlContent)));
    }

    // VULNERABLE: TransformerFactory processes external stylesheets
    public static void transformXml(String xsltPath) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.newTransformer(new StreamSource(xsltPath));
    }
}
