package com.ibm.forensic.service;

import com.ibm.forensic.dto.PresignedUrlRequest;
import com.ibm.forensic.dto.PresignedUrlResponse;
import com.ibm.forensic.exception.PresignedUrlGenerationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("S3PresignService")
class S3PresignServiceTest {

    private static final String BUCKET = "fraud-forensic-logs";
    private static final long   EXPIRY = 15L;

    @Mock
    private S3Presigner presigner;

    @Mock
    private PresignedPutObjectRequest presignedPutObjectRequest;

    private S3PresignService service;

    @BeforeEach
    void setUp() {
        service = new S3PresignService(presigner, BUCKET, EXPIRY);
    }

    private static PresignedUrlRequest validRequest() {
        return new PresignedUrlRequest("case-001", "transaction-logs.log", 2048L, "text/plain");
    }

    private void stubPresigner(String urlString) throws MalformedURLException {
        URL url = new URL(urlString);
        when(presignedPutObjectRequest.url()).thenReturn(url);
        when(presigner.presignPutObject(any(PutObjectPresignRequest.class)))
                .thenReturn(presignedPutObjectRequest);
    }

    @Nested
    @DisplayName("generatePresignedPutUrl — happy path")
    class HappyPath {

        @Test
        @DisplayName("returns a response with the pre-signed URL from S3Presigner")
        void returnsPresignedUrl() throws MalformedURLException {
            String expectedUrl = "https://fraud-forensic-logs.s3.amazonaws.com/fraud-logs/case-001/transaction-logs.log?X-Amz-Signature=abc123";
            stubPresigner(expectedUrl);
            PresignedUrlResponse response = service.generatePresignedPutUrl(validRequest());
            assertThat(response.presignedUrl()).isEqualTo(expectedUrl);
        }

        @Test
        @DisplayName("sets httpMethod to PUT")
        void setsHttpMethodToPut() throws MalformedURLException {
            stubPresigner("https://s3.example.com/fraud-logs/case-001/transaction-logs.log");
            PresignedUrlResponse response = service.generatePresignedPutUrl(validRequest());
            assertThat(response.httpMethod()).isEqualTo("PUT");
        }

        @Test
        @DisplayName("builds S3 key as fraud-logs/<caseId>/<fileName>")
        void buildsCorrectS3Key() throws MalformedURLException {
            stubPresigner("https://s3.example.com/key");
            PresignedUrlResponse response = service.generatePresignedPutUrl(validRequest());
            assertThat(response.s3Key()).isEqualTo("fraud-logs/case-001/transaction-logs.log");
        }

        @Test
        @DisplayName("expiresAt is set to approximately now + expiry duration")
        void expiresAtIsApproximatelyNowPlusExpiry() throws MalformedURLException {
            stubPresigner("https://s3.example.com/key");
            Instant before = Instant.now();
            PresignedUrlResponse response = service.generatePresignedPutUrl(validRequest());
            Instant after = Instant.now();
            assertThat(response.expiresAt())
                    .isAfterOrEqualTo(before.plusSeconds(EXPIRY * 60 - 2))
                    .isBeforeOrEqualTo(after.plusSeconds(EXPIRY * 60 + 2));
        }

        @Test
        @DisplayName("delegates to S3Presigner exactly once")
        void delegatesToPresignerOnce() throws MalformedURLException {
            stubPresigner("https://s3.example.com/key");
            service.generatePresignedPutUrl(validRequest());
            verify(presigner, times(1)).presignPutObject(any(PutObjectPresignRequest.class));
        }
    }

    @Nested
    @DisplayName("S3 key sanitisation")
    class KeySanitisation {

        @Test
        @DisplayName("strips forward slashes from fileName to prevent path traversal")
        void stripsForwardSlashes() throws MalformedURLException {
            PresignedUrlRequest req = new PresignedUrlRequest("case-007", "../malicious.log", 100L, "text/plain");
            stubPresigner("https://s3.example.com/key");
            PresignedUrlResponse response = service.generatePresignedPutUrl(req);
            assertThat(response.s3Key()).doesNotContain("../");
        }
    }

    @Nested
    @DisplayName("generatePresignedPutUrl — error path")
    class ErrorPath {

        @Test
        @DisplayName("wraps SDK RuntimeException in PresignedUrlGenerationException")
        void wrapsAwsSdkException() {
            when(presigner.presignPutObject(any(PutObjectPresignRequest.class)))
                    .thenThrow(new RuntimeException("AWS SDK error"));
            assertThatThrownBy(() -> service.generatePresignedPutUrl(validRequest()))
                    .isInstanceOf(PresignedUrlGenerationException.class)
                    .hasMessageContaining("fraud-logs/case-001/transaction-logs.log")
                    .hasCauseInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("exception message includes the S3 key for diagnosis")
        void exceptionMessageIncludesKey() {
            when(presigner.presignPutObject(any(PutObjectPresignRequest.class)))
                    .thenThrow(new RuntimeException("timeout"));
            assertThatThrownBy(() -> service.generatePresignedPutUrl(validRequest()))
                    .isInstanceOf(PresignedUrlGenerationException.class)
                    .hasMessageContaining("case-001");
        }
    }
}
