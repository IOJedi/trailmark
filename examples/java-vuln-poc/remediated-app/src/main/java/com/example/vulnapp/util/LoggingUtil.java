package com.example.vulnapp.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

/**
 * Centralised logging utility (patched version).
 *
 * PATCHED: log4j-core 2.17.2 has JNDI lookups disabled by default.
 * The {} placeholder syntax never invokes JNDI regardless of content.
 */
@Component
public class LoggingUtil {

    private static final Logger logger = LogManager.getLogger(LoggingUtil.class);

    /**
     * Log an access event for the given identifier.
     * Safe on log4j-core 2.17.2+: JNDI is disabled by default.
     */
    public void logAccess(String identifier) {
        logger.info("Access by user: {}", identifier);
    }

    /**
     * Log an error event (message sanitized by caller before this call).
     */
    public void logError(String message, Throwable cause) {
        logger.error("Error - {}", message, cause);
    }

    /**
     * Log a debug-level message.
     */
    public void logDebug(String detail) {
        logger.debug("Debug: {}", detail);
    }
}
