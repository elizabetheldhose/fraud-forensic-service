package com.ibm.forensic.controller;

import com.ibm.forensic.dto.PresignedUrlRequest;
import com.ibm.forensic.dto.PresignedUrlResponse;
import com.ibm.forensic.service.S3PresignService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller that exposes the pre-signed S3 upload URL endpoint.
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/uploads")
public class UploadController {

    private final S3PresignService s3PresignService;

    @PostMapping("/presigned-url")
    public ResponseEntity<PresignedUrlResponse> generatePresignedUrl(
            @Valid @RequestBody PresignedUrlRequest request) {

        log.info("Received pre-sign request — caseId={} fileName={} size={}",
                request.caseId(), request.fileName(), request.fileSizeBytes());

        PresignedUrlResponse response = s3PresignService.generatePresignedPutUrl(request);
        return ResponseEntity.ok(response);
    }
}
