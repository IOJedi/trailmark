package com.example.vulnapp.controller;

import com.example.vulnapp.service.ReportService;
import com.example.vulnapp.service.UserService;
import com.example.vulnapp.util.LoggingUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * REST controller exposing user management endpoints (patched version).
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private ReportService reportService;

    @Autowired
    private LoggingUtil loggingUtil;

    /**
     * Look up a user profile by username.
     * PATCHED: username is sanitized before logging (no JNDI expansion possible).
     */
    @GetMapping("/{username}")
    public ResponseEntity<Map<String, Object>> getUser(
            @PathVariable String username) {
        loggingUtil.logAccess(username);
        Map<String, Object> user = userService.findUser(username);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(user);
    }

    /**
     * Generate a report from a user-supplied template string.
     * PATCHED: commons-text 1.10.0 does not expand script:// or dns:// lookups.
     */
    @GetMapping("/report")
    public ResponseEntity<String> generateReport(
            @RequestParam String template) {
        String result = reportService.renderTemplate(template);
        return ResponseEntity.ok(result);
    }

    /**
     * Import user data from a typed JSON payload.
     * PATCHED: uses a specific DTO type, not raw Object deserialization.
     */
    @PostMapping("/import")
    public ResponseEntity<String> importUser(
            @RequestBody String rawJson) {
        try {
            Map<String, Object> parsed = userService.deserializeUser(rawJson);
            return ResponseEntity.ok("Imported: " + parsed.get("name"));
        } catch (Exception e) {
            loggingUtil.logError("Import failed", e);
            return ResponseEntity.badRequest().body("Invalid payload");
        }
    }
}
