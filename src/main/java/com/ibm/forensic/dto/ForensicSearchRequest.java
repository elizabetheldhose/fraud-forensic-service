package com.ibm.forensic.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Immutable request record for querying processed forensic results from
 * OpenSearch Serverless.
 *
 * @param caseId    Fraud-case identifier whose indexed documents should be searched.
 * @param query     Free-text query forwarded to OpenSearch multi-match.
 */
public record ForensicSearchRequest(

        @NotBlank(message = "caseId must not be blank")
        @Size(max = 64, message = "caseId must not exceed 64 characters")
        @Pattern(
                regexp = "^[a-zA-Z0-9\\-]+$",
                message = "caseId may only contain alphanumeric characters and hyphens"
        )
        String caseId,

        @NotBlank(message = "query must not be blank")
        @Size(max = 512, message = "query must not exceed 512 characters")
        String query
) {}
