package com.example.vuln;

public class UnsafeReflection {
    // INTENTIONAL: unsafe use of reflection with user-controlled class name
    public static Object createInstance(String className) throws Exception {
        // UNSAFE: loading classes based on unvalidated user input
        Class<?> cls = Class.forName(className);
        return cls.getDeclaredConstructor().newInstance();
    }
}
