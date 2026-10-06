package com.ibm.forensic.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.forensic.dto.ForensicSearchRequest;
import com.ibm.forensic.dto.ForensicSearchResponse;
import com.ibm.forensic.dto.ForensicSearchResponse.ForensicHit;
import com.ibm.forensic.exception.ForensicSearchException;
import com.ibm.forensic.exception.GlobalExceptionHandler;
import com.ibm.forensic.service.ForensicSearchService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = {ReportController.class, GlobalExceptionHandler.class})
@DisplayName("ReportController")
class ReportControllerTest {

    private static final String ENDPOINT = "/api/v1/reports/search";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private ForensicSearchService forensicSearchService;

    private static ForensicSearchRequest validRequest() {
        return new ForensicSearchRequest("case-001", "suspicious wire transfer");
    }

    private static ForensicSearchResponse stubSearchResponse() {
        ForensicHit hit = new ForensicHit(
                "doc-abc123",
                "fraud-logs/case-001/transaction-logs.log",
                1.75,
                "suspicious wire transfer of $50,000 detected"
        );
        return new ForensicSearchResponse("case-001", 1L, List.of(hit));
    }

    @Nested
    @DisplayName("POST /search — happy path")
    class HappyPath {

        @Test
        @DisplayName("returns 200 OK and the full ForensicSearchResponse JSON")
        void returns200WithFullResponseBody() throws Exception {
            when(forensicSearchService.searchAsync(any()))
                    .thenReturn(CompletableFuture.completedFuture(stubSearchResponse()));

            MvcResult asyncResult = mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(request().asyncStarted())
                    .andReturn();

            mockMvc.perform(asyncDispatch(asyncResult))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.caseId").value("case-001"))
                    .andExpect(jsonPath("$.totalHits").value(1))
                    .andExpect(jsonPath("$.hits", hasSize(1)))
                    .andExpect(jsonPath("$.hits[0].documentId").value("doc-abc123"))
                    .andExpect(jsonPath("$.hits[0].s3Key").value("fraud-logs/case-001/transaction-logs.log"))
                    .andExpect(jsonPath("$.hits[0].score").value(1.75))
                    .andExpect(jsonPath("$.hits[0].excerpt").value(containsString("suspicious wire transfer")));
        }

        @Test
        @DisplayName("delegates to ForensicSearchService exactly once with the request body")
        void delegatesToServiceOnce() throws Exception {
            when(forensicSearchService.searchAsync(any()))
                    .thenReturn(CompletableFuture.completedFuture(stubSearchResponse()));

            MvcResult asyncResult = mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(request().asyncStarted())
                    .andReturn();

            mockMvc.perform(asyncDispatch(asyncResult)).andExpect(status().isOk());
            verify(forensicSearchService, times(1)).searchAsync(any(ForensicSearchRequest.class));
        }

        @Test
        @DisplayName("returns empty hits array and zero totalHits when OpenSearch has no results")
        void returnsEmptyHitsWhenNoResults() throws Exception {
            ForensicSearchResponse emptyResponse =
                    new ForensicSearchResponse("case-001", 0L, List.of());
            when(forensicSearchService.searchAsync(any()))
                    .thenReturn(CompletableFuture.completedFuture(emptyResponse));

            MvcResult asyncResult = mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(request().asyncStarted())
                    .andReturn();

            mockMvc.perform(asyncDispatch(asyncResult))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalHits").value(0))
                    .andExpect(jsonPath("$.hits", hasSize(0)));
        }
    }

    @Nested
    @DisplayName("Validation — caseId")
    class CaseIdValidation {

        @Test
        @DisplayName("returns 400 when caseId is blank")
        void rejectBlankCaseId() throws Exception {
            ForensicSearchRequest req = new ForensicSearchRequest("", "wire transfer");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status").value(400))
                    .andExpect(jsonPath("$.message").value(containsString("caseId")));
        }

        @Test
        @DisplayName("returns 400 when caseId contains special characters")
        void rejectSpecialCharsCaseId() throws Exception {
            ForensicSearchRequest req = new ForensicSearchRequest("case_001; DROP TABLE", "query");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value(containsString("caseId")));
        }

        @Test
        @DisplayName("returns 400 when caseId exceeds 64 characters")
        void rejectOverlongCaseId() throws Exception {
            ForensicSearchRequest req = new ForensicSearchRequest("a".repeat(65), "query");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Validation — query")
    class QueryValidation {

        @Test
        @DisplayName("returns 400 when query is blank")
        void rejectBlankQuery() throws Exception {
            ForensicSearchRequest req = new ForensicSearchRequest("case-001", "");
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status").value(400))
                    .andExpect(jsonPath("$.message").value(containsString("query")));
        }

        @Test
        @DisplayName("returns 400 when query exceeds 512 characters")
        void rejectOverlongQuery() throws Exception {
            ForensicSearchRequest req = new ForensicSearchRequest("case-001", "q".repeat(513));
            mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Error propagation")
    class ErrorPropagation {

        @Test
        @DisplayName("returns 502 when ForensicSearchService throws ForensicSearchException")
        void returns502OnSearchFailure() throws Exception {
            CompletableFuture<ForensicSearchResponse> failedFuture = new CompletableFuture<>();
            failedFuture.completeExceptionally(
                    new ForensicSearchException("OpenSearch unreachable", new RuntimeException()));
            when(forensicSearchService.searchAsync(any())).thenReturn(failedFuture);

            MvcResult asyncResult = mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(request().asyncStarted())
                    .andReturn();

            mockMvc.perform(asyncDispatch(asyncResult))
                    .andExpect(status().isBadGateway())
                    .andExpect(jsonPath("$.status").value(502))
                    .andExpect(jsonPath("$.message").value(not(containsString("OpenSearch unreachable"))));
        }

        @Test
        @DisplayName("returns 500 and hides internal detail for unexpected exceptions")
        void returns500OnUnexpectedException() throws Exception {
            CompletableFuture<ForensicSearchResponse> failedFuture = new CompletableFuture<>();
            failedFuture.completeExceptionally(new RuntimeException("NullPointerException in internal chain"));
            when(forensicSearchService.searchAsync(any())).thenReturn(failedFuture);

            MvcResult asyncResult = mockMvc.perform(post(ENDPOINT)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(request().asyncStarted())
                    .andReturn();

            mockMvc.perform(asyncDispatch(asyncResult))
                    .andExpect(status().isInternalServerError())
                    .andExpect(jsonPath("$.message").value(not(containsString("NullPointerException"))));
        }
    }
}
