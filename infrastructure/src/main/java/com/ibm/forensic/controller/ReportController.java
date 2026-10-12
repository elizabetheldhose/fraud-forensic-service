package com.ibm.forensic.controller;

import com.ibm.forensic.dto.ForensicSearchRequest;
import com.ibm.forensic.dto.ForensicSearchResponse;
import com.ibm.forensic.service.ForensicSearchService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.CompletableFuture;

/**
 * REST controller that exposes the forensic search endpoint.
 *
 * <p>Responsibilities of this layer are intentionally narrow:
 * <ol>
 *   <li>Declare the route and HTTP verb.</li>
 *   <li>Trigger Jakarta Bean Validation via {@code @Valid}.</li>
 *   <li>Delegate to {@link ForensicSearchService#searchAsync} which executes
 *       the OpenSearch query on a Java 21 virtual thread.</li>
 *   <li>Return a {@code 200 OK} with the ranked results.</li>
 * </ol>
 * </p>
 *
 * <p><b>Security note:</b> This endpoint must sit behind an authentication
 * gateway (e.g. IBM APIC / API Connect with OAuth 2.0) in production.
 * No internal infrastructure details (index names, cluster URIs, scores
 * beyond relevance) are returned to the caller beyond what is strictly
 * required by the client.</p>
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/reports")
public class ReportController {

    private final ForensicSearchService forensicSearchService;

    /**
     * Searches the OpenSearch Serverless forensic index for documents matching
     * the supplied query within the given fraud case.
     *
     * <p>The underlying service call is dispatched on a virtual thread via
     * {@code @Async}, so this handler returns a {@link CompletableFuture} which
     * Spring MVC resolves asynchronously without holding a platform thread.</p>
     *
     * @param request search criteria; validated before the method body executes
     * @return 200 OK with {@link ForensicSearchResponse}
     */
    @PostMapping("/search")
    public CompletableFuture<ResponseEntity<ForensicSearchResponse>> search(
            @Valid @RequestBody ForensicSearchRequest request) {

        log.info("Received search request — caseId={}", request.caseId());

        return forensicSearchService.searchAsync(request)
                .thenApply(ResponseEntity::ok);
    }
}
