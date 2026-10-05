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
 *
 * <p>Responsibilities of this layer are intentionally narrow:
 * <ol>
 *   <li>Declare the route and HTTP verb.</li>
 *   <li>Trigger Jakarta Bean Validation via {@code @Valid}.</li>
 *   <li>Delegate all business logic to {@link S3PresignService}.</li>
 *   <li>Return a {@code 200 OK} with the pre-signed URL payload.</li>
 * </ol>
 * Error translation (400, 502, 500) is handled centrally by
 * {@link com.ibm.forensic.exception.GlobalExceptionHandler}.
 * </p>
 *
 * <p><b>Security note:</b> This endpoint must sit behind an authentication
 * gateway (e.g. IBM APIC / API Connect with OAuth 2.0) in production.
 * No credentials or internal infrastructure details are returned to the caller.</p>
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/uploads")
public class UploadController {

    private final S3PresignService s3PresignService;

    /**
     * Generates a short-lived pre-signed S3 PUT URL.
     *
     * <p>The frontend receives the URL and uploads the file directly to S3,
     * keeping binary payloads out of this service entirely.</p>
     *
     * @param request upload metadata; validated before the method body executes
     * @return 200 OK with {@link PresignedUrlResponse}
     */
    @PostMapping("/presigned-url")
    public ResponseEntity<PresignedUrlResponse> generatePresignedUrl(
            @Valid @RequestBody PresignedUrlRequest request) {

        log.info("Received pre-sign request — caseId={} fileName={} size={}",
                request.caseId(), request.fileName(), request.fileSizeBytes());

        PresignedUrlResponse response = s3PresignService.generatePresignedPutUrl(request);
        return ResponseEntity.ok(response);
    }
}
