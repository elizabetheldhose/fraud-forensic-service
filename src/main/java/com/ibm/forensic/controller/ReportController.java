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
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/reports")
public class ReportController {

    private final ForensicSearchService forensicSearchService;

    @PostMapping("/search")
    public CompletableFuture<ResponseEntity<ForensicSearchResponse>> search(
            @Valid @RequestBody ForensicSearchRequest request) {

        log.info("Received search request — caseId={}", request.caseId());

        return forensicSearchService.searchAsync(request)
                .thenApply(ResponseEntity::ok);
    }
}
