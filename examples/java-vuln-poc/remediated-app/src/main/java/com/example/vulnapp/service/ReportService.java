package com.example.vulnapp.service;

import org.apache.commons.text.StringSubstitutor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Generates text reports from templates (patched version).
 *
 * PATCHED: commons-text 1.10.0 removes the dangerous script:// and dns://
 * interpolators by default, so user-controlled input is safe to pass to
 * StringSubstitutor.replace().
 */
@Service
public class ReportService {

    private static final Map<String, String> CONTEXT = new HashMap<>();

    static {
        CONTEXT.put("appName", "VulnApp");
        CONTEXT.put("version", "1.1");
    }

    /**
     * Render a template string by substituting ${variable} placeholders.
     * Safe on commons-text 1.10.0+.
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
