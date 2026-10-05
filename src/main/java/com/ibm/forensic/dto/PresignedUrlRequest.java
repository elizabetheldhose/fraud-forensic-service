package com.ibm.forensic.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

/**
 * Immutable request record for pre-signed S3 upload URL generation.
 *
 * <p>Jakarta Bean Validation annotations are applied directly on record components;
 * Spring's {@code @Validated} triggers them before the method body executes.</p>
 *
 * @param caseId     Unique fraud-case identifier (alphanumeric + hyphens, max 64 chars).
 * @param fileName   Original file name supplied by the client; must end with .log or .json.
 * @param fileSizeBytes Declared upload size in bytes; used to pre-validate against bucket policy.
 * @param contentType MIME type of the file being uploaded.
 */
public record PresignedUrlRequest(

        @NotBlank(message = "caseId must not be blank")
        @Size(max = 64, message = "caseId must not exceed 64 characters")
        @Pattern(
                regexp = "^[a-zA-Z0-9\\-]+$",
                message = "caseId may only contain alphanumeric characters and hyphens"
        )
        String caseId,

        @NotBlank(message = "fileName must not be blank")
        @Size(max = 255, message = "fileName must not exceed 255 characters")
        @Pattern(
                regexp = "^[\\w\\-. ]+\\.(log|json)$",
                message = "fileName must be a .log or .json file with safe characters only"
        )
        String fileName,

        @Positive(message = "fileSizeBytes must be a positive integer")
        long fileSizeBytes,

        @NotBlank(message = "contentType must not be blank")
        @Pattern(
                regexp = "^(application/json|text/plain)$",
                message = "contentType must be application/json or text/plain"
        )
        String contentType
) {}
