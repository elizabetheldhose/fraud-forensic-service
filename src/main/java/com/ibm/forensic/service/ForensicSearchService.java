package com.ibm.forensic.service;

import com.ibm.forensic.dto.ForensicSearchRequest;
import com.ibm.forensic.dto.ForensicSearchResponse;
import com.ibm.forensic.dto.ForensicSearchResponse.ForensicHit;
import com.ibm.forensic.exception.ForensicSearchException;
import lombok.extern.slf4j.Slf4j;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.query_dsl.BoolQuery;
import org.opensearch.client.opensearch._types.query_dsl.MatchQuery;
import org.opensearch.client.opensearch._types.query_dsl.Query;
import org.opensearch.client.opensearch.core.SearchRequest;
import org.opensearch.client.opensearch.core.SearchResponse;
import org.opensearch.client.opensearch.core.search.Hit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Service that queries the OpenSearch Serverless collection produced by the
 * upstream Lambda processing pipeline.
 *
 * <h2>Threading model</h2>
 * <p>With {@code spring.threads.virtual.enabled=true} (Spring Boot 3.2+), the
 * Tomcat request threads <em>and</em> the default {@code @Async} executor are
 * both backed by Java 21 virtual threads.  The {@link #searchAsync} method is
 * annotated {@link Async} so that its blocking OpenSearch HTTP call is dispatched
 * to that virtual-thread executor, freeing the calling carrier thread immediately
 * and preventing blocking I/O from stalling the platform thread pool under load.</p>
 *
 * <h2>Query structure</h2>
 * <p>A {@code bool} query is composed of:
 * <ul>
 *   <li>A {@code match} filter on the {@code caseId} field — uses analyzed matching
 *       so it works regardless of how OpenSearch mapped the field.</li>
 *   <li>A {@code match} clause on the {@code content} field — full-text relevance
 *       ranking against the query string.</li>
 * </ul>
 * </p>
 *
 * <h2>Security</h2>
 * <p>The OpenSearch client bean (see {@link com.ibm.forensic.config.AwsConfig})
 * uses AWS SigV4 signing via {@code AwsSdk2Transport}, so every request carries
 * short-lived IAM credentials resolved by {@code DefaultCredentialsProvider}
 * (env vars → instance profile → IAM role). No credentials are stored here.</p>
 */
@Slf4j
@Service
public class ForensicSearchService {

    private static final String FIELD_CASE_ID = "caseId";
    private static final String FIELD_CONTENT = "content";
    private static final String FIELD_S3_KEY  = "s3Key";
    private static final String FIELD_EXCERPT = "excerpt";

    private final OpenSearchClient openSearchClient;
    private final String indexName;
    private final int maxResults;

    public ForensicSearchService(
            OpenSearchClient openSearchClient,
            @Value("${aws.opensearch.index}") String indexName,
            @Value("${aws.opensearch.max-results:20}") int maxResults) {
        this.openSearchClient = openSearchClient;
        this.indexName        = indexName;
        this.maxResults       = maxResults;
    }

    /**
     * Executes a full-text search against the forensic index asynchronously on a
     * virtual thread.  The {@link CompletableFuture} completes with a
     * {@link ForensicSearchResponse} on success, or completes exceptionally with
     * a {@link ForensicSearchException} if the OpenSearch call fails.
     *
     * @param request validated search criteria from the controller
     * @return a future carrying the ranked search results
     */
    @Async
    public CompletableFuture<ForensicSearchResponse> searchAsync(ForensicSearchRequest request) {
        log.info("OpenSearch query — index={} caseId={} query='{}'",
                indexName, request.caseId(), request.query());
        try {
            SearchResponse<Map> response = openSearchClient.search(buildSearchRequest(request), Map.class);
            ForensicSearchResponse result = mapResponse(request.caseId(), response);
            log.info("OpenSearch query complete — caseId={} totalHits={}",
                    request.caseId(), result.totalHits());
            return CompletableFuture.completedFuture(result);
        } catch (IOException ex) {
            throw new ForensicSearchException(
                    "OpenSearch query failed for caseId=" + request.caseId(), ex);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private SearchRequest buildSearchRequest(ForensicSearchRequest request) {
        // match filter on caseId: works with both keyword and analyzed text mappings
        Query caseFilter = Query.of(q -> q.match(
                MatchQuery.of(m -> m.field(FIELD_CASE_ID)
                        .query(FieldValue.of(request.caseId())))));

        // match query: full-text relevance ranking on the indexed document content
        Query contentMatch = Query.of(q -> q.match(
                MatchQuery.of(m -> m.field(FIELD_CONTENT)
                        .query(FieldValue.of(request.query())))));

        Query boolQuery = Query.of(q -> q.bool(
                BoolQuery.of(b -> b.filter(caseFilter).must(contentMatch))));

        return SearchRequest.of(s -> s
                .index(indexName)
                .size(maxResults)
                .query(boolQuery));
    }

    @SuppressWarnings("unchecked")
    private ForensicSearchResponse mapResponse(String caseId, SearchResponse<Map> response) {
        long total = response.hits().total() != null
                ? response.hits().total().value()
                : 0L;

        List<ForensicHit> hits = response.hits().hits().stream()
                .map(this::toForensicHit)
                .toList();

        return new ForensicSearchResponse(caseId, total, hits);
    }

    @SuppressWarnings("unchecked")
    private ForensicHit toForensicHit(Hit<Map> hit) {
        Map<String, Object> source = hit.source() != null ? hit.source() : Map.of();
        String s3Key  = (String) source.getOrDefault(FIELD_S3_KEY, "");
        String excerpt = (String) source.getOrDefault(FIELD_EXCERPT, "");
        double score  = hit.score() != null ? hit.score() : 0.0;
        return new ForensicHit(hit.id(), s3Key, score, excerpt);
    }
}
