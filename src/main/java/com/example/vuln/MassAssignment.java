package com.example.vuln;

import java.lang.reflect.Field;
import java.util.Map;

/**
 * Demonstrates mass assignment / parameter binding vulnerabilities.
 * This file intentionally contains vulnerable code for SAST testing.
 */
public class MassAssignment {

    public static class User {
        public String username;
        public String email;
        public String role = "user";        // should not be user-settable
        public boolean isAdmin = false;     // should not be user-settable
        public String passwordHash;
    }

    // VULNERABLE: Binds all request parameters to model fields without allowlist
    public static User bindAll(User user, Map<String, String> params) throws Exception {
        for (Map.Entry<String, String> entry : params.entrySet()) {
            Field field = User.class.getDeclaredField(entry.getKey()); // UNSAFE: attacker sets role/isAdmin
            field.setAccessible(true);
            field.set(user, entry.getValue());
        }
        return user;
    }

    // VULNERABLE: Copies all JSON properties onto object including privileged fields
    public static User fromJson(String json) throws Exception {
        return new com.fasterxml.jackson.databind.ObjectMapper()
            .readerForUpdating(new User())
            .readValue(json); // UNSAFE: no @JsonIgnore on sensitive fields
    }
}
