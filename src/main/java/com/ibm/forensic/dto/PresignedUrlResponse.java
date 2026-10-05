package com.ibm.forensic.dto;

import java.time.Instant;

/**
 * Immutable response record carrying the pre-signed URL and associated metadata.
 *
 * @param presignedUrl  HTTPS URL the frontend uses to PUT the file directly to S3.
 * @param s3Key         Full object key the file will be stored under in the bucket.
 * @param expiresAt     Exact instant at which the pre-signed URL expires.
 * @param httpMethod    HTTP method the client must use (always {@code PUT} here).
 */
public record PresignedUrlResponse(
        String presignedUrl,
        String s3Key,
        Instant expiresAt,
        String httpMethod
) {}
