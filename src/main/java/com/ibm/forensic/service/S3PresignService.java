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

    private String buildS3Key(String caseId, String fileName) {
        String safeFileName = fileName.replaceAll("[/\\\\]", "_");
        return "%s/%s/%s".formatted(KEY_PREFIX, caseId, safeFileName);
    }
}
