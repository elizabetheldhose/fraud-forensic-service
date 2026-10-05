package com.ibm.forensic.dto;

import java.time.Instant;

/**
 * Structured error body returned for all 4xx / 5xx responses.
 *
 * @param status    HTTP status code.
 * @param error     Short error label (e.g. "Bad Request").
 * @param message   Human-readable detail safe to expose to the client.
 * @param timestamp Time the error was generated.
 */
public record ApiErrorResponse(
        int status,
        String error,
        String message,
        Instant timestamp
) {
    public static ApiErrorResponse of(int status, String error, String message) {
        return new ApiErrorResponse(status, error, message, Instant.now());
    }
}
