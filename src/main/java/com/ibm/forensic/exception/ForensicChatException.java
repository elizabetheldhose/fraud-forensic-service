package com.ibm.forensic.exception;

/**
 * Thrown when the Bedrock streaming invocation fails at the transport or
 * application level. Maps to HTTP 502 Bad Gateway in
 * {@link GlobalExceptionHandler}.
 */
public class ForensicChatException extends RuntimeException {

    public ForensicChatException(String message, Throwable cause) {
        super(message, cause);
    }
}
