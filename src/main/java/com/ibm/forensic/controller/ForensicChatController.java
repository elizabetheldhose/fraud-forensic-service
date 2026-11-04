package com.ibm.forensic.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.forensic.dto.ForensicChatRequest;
import com.ibm.forensic.service.ForensicRagService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;

import java.io.IOException;

/**
 * REST controller that exposes the forensic RAG chat endpoint.
 *
 * <h2>Streaming protocol</h2>
 * <p>The response uses {@link ResponseBodyEmitter} with
 * {@code text/event-stream} so that each Bedrock token delta is pushed to the
 * client as an SSE data frame the moment it arrives, without buffering the full
 * generation.  Clients should consume the stream incrementally (e.g., the
 * browser's {@code EventSource} API or {@code curl --no-buffer}).</p>
 *
 * <h2>Threading</h2>
 * <p>With {@code spring.threads.virtual.enabled=true} the Tomcat servlet thread
 * is a virtual thread.  The emitter is handed off immediately; the RAG pipeline
 * runs asynchronously and calls {@link ResponseBodyEmitter#send} on the Netty
 * event-loop thread used by the AWS async client — all virtual-thread friendly.</p>
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/forensics")
public class ForensicChatController {

    /** Emitter timeout in milliseconds — 5 minutes; sized for large case analyses. */
    private static final long EMITTER_TIMEOUT_MS = 5 * 60 * 1_000L;

    private final ForensicRagService forensicRagService;
    private final ObjectMapper objectMapper;

    /**
     * Streams a forensic RAG analysis as Server-Sent Events.
     *
     * <p>Each SSE frame contains one or more token deltas produced by
     * {@code anthropic.claude-3-5-sonnet-v2} grounded on the top-N OpenSearch
     * evidence excerpts for the given {@code caseId}.</p>
     *
     * @param request validated chat request body
     * @return a {@link ResponseBodyEmitter} that streams {@code text/event-stream}
     */
    @PostMapping(path = "/chat", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public ResponseBodyEmitter chat(@Valid @RequestBody ForensicChatRequest request) {
        log.info("Chat stream request — caseId={}", request.caseId());

        ResponseBodyEmitter emitter = new ResponseBodyEmitter(EMITTER_TIMEOUT_MS);

        forensicRagService
                .streamAnalysis(request, token -> sendToken(emitter, token))
                .whenComplete((ignored, ex) -> {
                    if (ex != null) {
                        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                        log.error("Chat stream error — caseId={}", request.caseId(), cause);
                        emitter.completeWithError(cause);
                    } else {
                        log.info("Chat stream complete — caseId={}", request.caseId());
                        emitter.complete();
                    }
                });

        return emitter;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void sendToken(ResponseBodyEmitter emitter, String token) {
        try {
            // JSON-encode the token so embedded newlines can never break SSE framing
            emitter.send("data: " + objectMapper.writeValueAsString(token) + "\n\n",
                    MediaType.TEXT_EVENT_STREAM);
        } catch (IOException ex) {
            // Client disconnected — log at debug; the stream will terminate naturally.
            log.debug("Emitter send failed (client may have disconnected)", ex);
            emitter.completeWithError(ex);
        }
    }
}
