package com.example.vulnapp.controller;

import com.example.vulnapp.service.ReportService;
import com.example.vulnapp.service.UserService;
import com.example.vulnapp.util.LoggingUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
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
 * REST controller exposing user management endpoints.
 * Vulnerable to Log4Shell, Text4Shell, and Jackson deserialization issues.
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

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Look up a user profile by username.
     * VULNERABILITY: username is passed directly to Log4j logger (Log4Shell).
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
     * VULNERABILITY: template is passed to Commons-Text StringSubstitutor
     * (Text4Shell / CVE-2022-42889).
     */
    @GetMapping("/report")
    public ResponseEntity<String> generateReport(
            @RequestParam String template) {
        String result = reportService.renderTemplate(template);
        return ResponseEntity.ok(result);
    }

    /**
     * Deserialize a raw JSON payload into an arbitrary Object.
     * VULNERABILITY: polymorphic deserialization without type restrictions
     * (CVE-2022-42003 / jackson-databind gadget chains).
     */
    @PostMapping("/import")
    public ResponseEntity<String> importUser(
            @RequestBody String rawJson) {
        try {
            Object parsed = userService.deserializeUser(rawJson);
            return ResponseEntity.ok("Imported: " + parsed.toString());
        } catch (Exception e) {
            loggingUtil.logError("Import failed for payload: " + rawJson, e);
            return ResponseEntity.badRequest().body("Invalid payload");
        }
    }
}
