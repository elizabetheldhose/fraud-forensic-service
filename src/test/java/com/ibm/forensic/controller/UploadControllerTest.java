package com.ibm.forensic.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.forensic.dto.PresignedUrlRequest;
import com.ibm.forensic.dto.PresignedUrlResponse;
import com.ibm.forensic.exception.GlobalExceptionHandler;
import com.ibm.forensic.exception.PresignedUrlGenerationException;
import com.ibm.forensic.service.S3PresignService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = {UploadController.class, GlobalExceptionHandler.class})
@DisplayName("UploadController")
class UploadControllerTest {

    private static final String ENDPOINT = "/api/v1/uploads/presigned-url";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private S3PresignService s3PresignService;

    private static PresignedUrlRequest validRequest() {
        return new PresignedUrlRequest("case-001", "transaction-logs.log", 2048L, "text/plain");
    }

    private static PresignedUrlResponse stubResponse() {
        return new PresignedUrlResponse(
                "https://fraud-forensic-logs.s3.amazonaws.com/fraud-logs/case-001/transaction-logs.log?sig=abc",
                "fraud-logs/case-001/transaction-logs.log",
                Instant.parse("2025-01-01T12:15:00Z"),
                "PUT"
        );
    }

    @Nested
    @DisplayName("POST /presigned-url — happy path")
    class HappyPath {

        @Test
        @DisplayName("returns 200 OK with pre-signed URL response body")
        void returns200WithBody() throws Exception {
            when(s3PresignService.generatePresignedPutUrl(any())).thenReturn(stubResponse());
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.presignedUrl").value(containsString("s3.amazonaws.com")))
                    .andExpect(jsonPath("$.s3Key").value("fraud-logs/case-001/transaction-logs.log"))
                    .andExpect(jsonPath("$.httpMethod").value("PUT"))
                    .andExpect(jsonPath("$.expiresAt").exists());
        }

        @Test
        @DisplayName("delegates exactly once to S3PresignService")
        void delegatesToService() throws Exception {
            when(s3PresignService.generatePresignedPutUrl(any())).thenReturn(stubResponse());
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(status().isOk());
            verify(s3PresignService, times(1)).generatePresignedPutUrl(any(PresignedUrlRequest.class));
        }
    }

    @Nested
    @DisplayName("Validation — caseId")
    class CaseIdValidation {

        @Test
        @DisplayName("returns 400 when caseId is blank")
        void rejectBlankCaseId() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("", "valid.log", 1L, "text/plain");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status").value(400));
        }

        @Test
        @DisplayName("returns 400 when caseId exceeds 64 characters")
        void rejectOverlongCaseId() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("a".repeat(65), "valid.log", 1L, "text/plain");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("returns 400 when caseId contains special characters")
        void rejectSpecialCharsCaseId() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("case_001; DROP TABLE", "valid.log", 1L, "text/plain");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value(containsString("caseId")));
        }
    }

    @Nested
    @DisplayName("Validation — fileName")
    class FileNameValidation {

        @Test
        @DisplayName("returns 400 when fileName has a disallowed extension")
        void rejectDisallowedExtension() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("case-001", "malware.exe", 1L, "text/plain");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value(containsString("fileName")));
        }

        @Test
        @DisplayName("accepts .json fileName")
        void acceptJsonExtension() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("case-002", "events.json", 512L, "application/json");
            when(s3PresignService.generatePresignedPutUrl(any())).thenReturn(stubResponse());
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("returns 400 when fileName is blank")
        void rejectBlankFileName() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("case-001", "  ", 1L, "text/plain");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Validation — fileSizeBytes")
    class FileSizeValidation {

        @Test
        @DisplayName("returns 400 when fileSizeBytes is zero")
        void rejectZeroSize() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("case-001", "data.log", 0L, "text/plain");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value(containsString("fileSizeBytes")));
        }

        @Test
        @DisplayName("returns 400 when fileSizeBytes is negative")
        void rejectNegativeSize() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("case-001", "data.log", -100L, "text/plain");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Validation — contentType")
    class ContentTypeValidation {

        @Test
        @DisplayName("returns 400 for a disallowed MIME type")
        void rejectDisallowedMimeType() throws Exception {
            PresignedUrlRequest req = new PresignedUrlRequest("case-001", "data.log", 100L, "application/octet-stream");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value(containsString("contentType")));
        }
    }

    @Nested
    @DisplayName("Error propagation")
    class ErrorPropagation {

        @Test
        @DisplayName("returns 502 when S3PresignService throws PresignedUrlGenerationException")
        void returns502OnServiceFailure() throws Exception {
            when(s3PresignService.generatePresignedPutUrl(any()))
                    .thenThrow(new PresignedUrlGenerationException("AWS down", new RuntimeException()));
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(status().isBadGateway())
                    .andExpect(jsonPath("$.status").value(502))
                    .andExpect(jsonPath("$.message").value(not(containsString("AWS down"))));
        }

        @Test
        @DisplayName("returns 500 and hides details for unexpected exceptions")
        void returns500OnUnexpectedException() throws Exception {
            when(s3PresignService.generatePresignedPutUrl(any()))
                    .thenThrow(new RuntimeException("NullPointerException in internal chain"));
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.message").value(not(containsString("NullPointerException"))));
        }
    }
}
