package com.ibm.forensic.exception;

/**
 * Thrown when the S3 pre-signer cannot generate a URL for a valid request.
 * Maps to HTTP 502 Bad Gateway in the global exception handler.
 */
public class PresignedUrlGenerationException extends RuntimeException {

    public PresignedUrlGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
