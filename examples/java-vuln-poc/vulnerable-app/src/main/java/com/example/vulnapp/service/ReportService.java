package com.example.vulnapp.service;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Generates text reports from templates supplied by the caller.
 *
 * VULNERABILITY: StringSubstitutor.replace() with user-controlled input
 * can expand script:// and dns:// lookups on commons-text 1.5-1.9
 * (CVE-2022-42889, "Text4Shell").
 */
@Service
public class ReportService {

    private static final Map<String, String> CONTEXT = new HashMap<>();

    static {
        CONTEXT.put("appName", "VulnApp");
        CONTEXT.put("version", "1.0");
    }

    /**
     * Render a template string by substituting ${variable} placeholders
     * and also expanding any special lookup expressions.
     */
    public String renderTemplate(String template) {
        StringSubstitutor substitutor = new StringSubstitutor(CONTEXT);
        return substitutor.replace(template);
    }

    /**
     * Build a standard usage report with static context.
     */
    public String buildUsageReport() {
        return renderTemplate(
                "App: ${appName} v${version} - Usage Report");
    }
}
