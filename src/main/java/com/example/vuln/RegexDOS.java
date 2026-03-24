package com.example.vuln;

import java.util.regex.Pattern;

/**
 * Demonstrates Regular Expression Denial of Service (ReDoS) vulnerabilities.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class RegexDOS {

    // VULNERABLE: Catastrophic backtracking with nested quantifiers on user input
    public static boolean validateEmail(String input) {
        return input.matches("^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\\.[a-zA-Z]{2,}$"); // UNSAFE: nested quantifiers
    }

    // VULNERABLE: Polynomial backtracking regex compiled from user input
    public static boolean matchPattern(String userPattern, String input) {
        return Pattern.compile(userPattern).matcher(input).matches(); // UNSAFE: user controls regex
    }

    // VULNERABLE: Evil regex — (a+)+ causes exponential backtracking
    public static boolean checkUsername(String username) {
        return username.matches("^(a+)+$"); // UNSAFE: ReDoS via input like "aaaaaaaaaaaaaaaa!"
    }

    // VULNERABLE: User-supplied regex used without timeout or complexity check
    public static String replaceAll(String input, String regex, String replacement) {
        return input.replaceAll(regex, replacement); // UNSAFE: user-controlled regex
    }
}
