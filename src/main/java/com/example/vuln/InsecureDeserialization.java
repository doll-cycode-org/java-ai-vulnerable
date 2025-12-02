package com.example.vuln;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class InsecureDeserialization {
    // INTENTIONAL: Reads serialized object from untrusted input
    public static Object unsafeDeserialize(byte[] data) throws Exception {
        // Unsafe: deserializing untrusted data may lead to remote code execution
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        }
    }
}
