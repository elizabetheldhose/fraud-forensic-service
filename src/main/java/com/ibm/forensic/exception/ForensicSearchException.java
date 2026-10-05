package com.ibm.forensic.exception;

/**
 * Thrown when the OpenSearch Serverless query fails at the transport or
 * application level. Maps to HTTP 502 Bad Gateway in
 * {@link GlobalExceptionHandler}.
 */
public class ForensicSearchException extends RuntimeException {

    public ForensicSearchException(String message, Throwable cause) {
        super(message, cause);
    }
}
