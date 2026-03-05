package com.borelli.jwsgenerator.exception;

/**
 * Thrown when a JWS generation or verification operation fails.
 */
public class JwsOperationException extends RuntimeException {

    public JwsOperationException(String message) {
        super(message);
    }

    public JwsOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
