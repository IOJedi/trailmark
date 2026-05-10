package com.example.vulnapp.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

/**
 * Centralised logging utility.
 *
 * VULNERABILITY: logger.info() and logger.error() calls with unsanitized
 * user input on log4j-core 2.0-2.14.1 trigger JNDI lookup expansion
 * (CVE-2021-44228, "Log4Shell").
 */
@Component
public class LoggingUtil {

    private static final Logger logger = LogManager.getLogger(LoggingUtil.class);

    /**
     * Log an access event for the given identifier.
     * Passing user-controlled data triggers Log4Shell on vulnerable versions.
     */
    public void logAccess(String identifier) {
        logger.info("Access by user: {}", identifier);
    }

    /**
     * Log an error with a message and associated exception.
     * Passing user-controlled data in message triggers Log4Shell.
     */
    public void logError(String message, Throwable cause) {
        logger.error("Error - {}", message, cause);
    }

    /**
     * Log a debug-level message (lower severity path).
     */
    public void logDebug(String detail) {
        logger.debug("Debug: {}", detail);
    }
}
