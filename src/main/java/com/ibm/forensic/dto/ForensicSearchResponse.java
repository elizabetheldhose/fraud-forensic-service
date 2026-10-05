package com.ibm.forensic.dto;

import java.util.List;

/**
 * Immutable response record carrying the ranked forensic search results.
 *
 * @param caseId       The queried fraud-case identifier.
 * @param totalHits    Total number of matching documents in the index.
 * @param hits         Ordered list of individual result hits.
 */
public record ForensicSearchResponse(
        String caseId,
        long totalHits,
        List<ForensicHit> hits
) {

    /**
     * A single document hit returned from OpenSearch.
     *
     * @param documentId  OpenSearch document {@code _id}.
     * @param s3Key       Original S3 object key the document was derived from.
     * @param score       Relevance score assigned by OpenSearch.
     * @param excerpt     Short text excerpt from the indexed document source.
     */
    public record ForensicHit(
            String documentId,
            String s3Key,
            double score,
            String excerpt
    ) {}
}
