package com.ibm.forensic.service;

import com.ibm.forensic.dto.PresignedUrlRequest;
import com.ibm.forensic.dto.PresignedUrlResponse;
import com.ibm.forensic.exception.PresignedUrlGenerationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

import java.time.Duration;
import java.time.Instant;

/**
 * Service responsible for generating pre-signed S3 PUT URLs.
 *
 * <p>Design decisions:
 * <ul>
 *   <li>The S3 object key is deterministically derived from {@code caseId} and
 *       {@code fileName} so that duplicate uploads overwrite the same object
 *       rather than creating orphaned copies.</li>
 *   <li>The URL validity window ({@code s3.presign.expiry-minutes}) is
 *       externalised to application properties and defaults to 15 minutes —
 *       short enough to limit the blast radius of a leaked URL.</li>
 *   <li>All AWS SDK calls are made on the calling (virtual) thread; the SDK
 *       uses non-blocking HTTP under the hood, so virtual-thread pinning is
 *       not a concern here.</li>
 * </ul>
 * </p>
 */
@Slf4j
@Service
public class S3PresignService {

    private static final String KEY_PREFIX = "fraud-logs";

    private final S3Presigner presigner;
    private final String bucketName;
    private final Duration urlExpiry;

    public S3PresignService(
            S3Presigner presigner,
            @Value("${aws.s3.bucket-name}") String bucketName,
            @Value("${aws.s3.presign.expiry-minutes:15}") long expiryMinutes) {
        this.presigner  = presigner;
        this.bucketName = bucketName;
        this.urlExpiry  = Duration.ofMinutes(expiryMinutes);
    }

    /**
     * Generates a pre-signed HTTPS PUT URL that the frontend can use to upload
     * a file directly to S3 without routing the bytes through this service.
     *
     * @param request validated upload metadata from the controller
     * @return {@link PresignedUrlResponse} containing the URL and expiry metadata
     * @throws PresignedUrlGenerationException if the AWS SDK call fails
     */
    public PresignedUrlResponse generatePresignedPutUrl(PresignedUrlRequest request) {
        String s3Key = buildS3Key(request.caseId(), request.fileName());
        log.info("Generating pre-signed PUT URL — bucket={} key={} expiry={}",
                bucketName, s3Key, urlExpiry);

        try {
            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucketName)
                    .key(s3Key)
                    .contentType(request.contentType())
                    .contentLength(request.fileSizeBytes())
                    .build();

            PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                    .signatureDuration(urlExpiry)
                    .putObjectRequest(putObjectRequest)
                    .build();

            PresignedPutObjectRequest presigned = presigner.presignPutObject(presignRequest);

            Instant expiresAt = Instant.now().plus(urlExpiry);
            String url = presigned.url().toString();

            log.info("Pre-signed URL generated successfully — key={} expiresAt={}", s3Key, expiresAt);

            return new PresignedUrlResponse(url, s3Key, expiresAt, "PUT");

        } catch (Exception ex) {
            throw new PresignedUrlGenerationException(
                    "Failed to generate pre-signed URL for key: " + s3Key, ex);
        }
    }

    /**
     * Builds a deterministic S3 object key that is safe against path-traversal attacks.
     * Format: {@code fraud-logs/<caseId>/<sanitisedFileName>}
     */
    private String buildS3Key(String caseId, String fileName) {
        // Strip any remaining path separators that slipped past validation
        String safeFileName = fileName.replaceAll("[/\\\\]", "_");
        return "%s/%s/%s".formatted(KEY_PREFIX, caseId, safeFileName);
    }
}
