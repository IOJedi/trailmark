package com.example.vulnapp.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * User business logic service (patched version).
 */
@Service
public class UserService {

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
     * PATCHED: Use JsonMapper with default safe configuration.
     * Default typing is NOT enabled; the return type is a typed Map.
     */
    private final ObjectMapper objectMapper = JsonMapper.builder().build();

    /**
     * Find a user in the in-memory store.
     */
    public Map<String, Object> findUser(String username) {
        return USER_STORE.get(username.toLowerCase());
    }

    /**
     * Deserialize raw JSON into a typed Map, not a raw Object.
     * PATCHED: no polymorphic type handling; gadget chains are not possible.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> deserializeUser(String rawJson) throws Exception {
        return objectMapper.readValue(rawJson, Map.class);
    }

    /**
     * Serialize a user map to JSON.
     */
    public String serializeUser(Map<String, Object> user) throws Exception {
        return objectMapper.writeValueAsString(user);
    }
}
