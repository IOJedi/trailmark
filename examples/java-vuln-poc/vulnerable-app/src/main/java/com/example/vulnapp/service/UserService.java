package com.example.vulnapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * User business logic service.
 * Contains a vulnerable Jackson deserialization call.
 */
@Service
public class UserService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final Map<String, Map<String, Object>> USER_STORE = new HashMap<>();

    static {
        Map<String, Object> alice = new HashMap<>();
        alice.put("name", "Alice");
        alice.put("role", "admin");
        USER_STORE.put("alice", alice);

        Map<String, Object> bob = new HashMap<>();
        bob.put("name", "Bob");
        bob.put("role", "user");
        USER_STORE.put("bob", bob);
    }

    /**
     * Find a user in the in-memory store.
     */
    public Map<String, Object> findUser(String username) {
        return USER_STORE.get(username.toLowerCase());
    }

    /**
     * Deserialize a raw JSON string into an arbitrary Object type.
     *
     * VULNERABILITY: Using Object.class with enableDefaultTyping allows
     * gadget-chain deserialization attacks (CVE-2022-42003, CVE-2022-42004).
     */
    @SuppressWarnings("deprecation")
    public Object deserializeUser(String rawJson) throws Exception {
        objectMapper.enableDefaultTyping(
                ObjectMapper.DefaultTyping.NON_FINAL);
        return objectMapper.readValue(rawJson, Object.class);
    }

    /**
     * Serialize a user map to JSON.
     */
    public String serializeUser(Map<String, Object> user) throws Exception {
        return objectMapper.writeValueAsString(user);
    }
}
