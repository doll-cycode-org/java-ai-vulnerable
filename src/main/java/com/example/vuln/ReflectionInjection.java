package com.example.vuln;

import java.lang.reflect.Method;

/**
 * Demonstrates unsafe use of Java reflection with user-controlled input.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class ReflectionInjection {

    // VULNERABLE: User-controlled class name loaded via reflection
    public static Object instantiateClass(String className) throws Exception {
        return Class.forName(className).getDeclaredConstructor().newInstance(); // UNSAFE: arbitrary class load
    }

    // VULNERABLE: User-controlled method name invoked via reflection
    public static Object invokeMethod(Object target, String methodName, Object... args) throws Exception {
        Method method = target.getClass().getMethod(methodName); // UNSAFE: attacker controls method name
        return method.invoke(target, args);
    }

    // VULNERABLE: Loads class from user-supplied URL (remote code execution risk)
    public static Class<?> loadFromUrl(String url) throws Exception {
        return new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL(url)}).loadClass("Payload"); // UNSAFE
    }
}
