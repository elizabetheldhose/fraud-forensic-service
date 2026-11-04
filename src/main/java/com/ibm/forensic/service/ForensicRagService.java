package com.ibm.forensic.service;

import com.ibm.forensic.dto.ForensicChatRequest;
import com.ibm.forensic.dto.ForensicSearchRequest;
import com.ibm.forensic.dto.ForensicSearchResponse.ForensicHit;
import com.ibm.forensic.exception.ForensicChatException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeAsyncClient;
import software.amazon.awssdk.services.bedrockruntime.model.ContentBlock;
import software.amazon.awssdk.services.bedrockruntime.model.ConversationRole;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseStreamRequest;
import software.amazon.awssdk.services.bedrockruntime.model.ConverseStreamResponseHandler;
import software.amazon.awssdk.services.bedrockruntime.model.Message;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Retrieval-Augmented Generation service.
 *
 * <h2>Flow</h2>
 * <ol>
 *   <li><b>Retrieve</b> — delegates to {@link ForensicSearchService#searchAsync} to
 *       fetch the top-{@code N} forensic document excerpts from OpenSearch Serverless.</li>
 *   <li><b>Augment</b> — compiles the ranked excerpts into a structured system prompt
 *       that provides the model with scoped evidence context.</li>
 *   <li><b>Generate</b> — invokes {@code ConverseStream} on the Bedrock async client,
 *       forwarding each text delta to the supplied {@link StreamTokenConsumer} as it
 *       arrives over the HTTP/2 event stream.</li>
 * </ol>
 *
 * <h2>Threading model</h2>
 * <p>With {@code spring.threads.virtual.enabled=true} the calling Tomcat thread is
 * already a virtual thread.  The {@link CompletableFuture} returned by
 * {@link ForensicSearchService#searchAsync} and the AWS async client both use
 * non-blocking I/O internally; no platform threads are blocked at any point.</p>
 *
 * <h2>Security</h2>
 * <p>Credentials are resolved by the {@link BedrockRuntimeAsyncClient} bean via
 * {@code DefaultCredentialsProvider} (env vars → instance profile → IAM role).
 * No credentials are stored in this class.</p>
 */
@Slf4j
@Service
public class ForensicRagService {

    /**
     * Functional interface for streaming token output.
     * Implemented by the controller as a {@link org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter}
     * send callback.
     */
    @FunctionalInterface
    public interface StreamTokenConsumer {
        /**
         * Called for each text token delta received from the model.
         *
         * @param token the partial text fragment; never {@code null} or empty
         */
        void accept(String token);
    }

    // Maximum number of search hits to include in the context window.
    private static final int MAX_CONTEXT_HITS = 10;

    // Hard character ceiling for a single excerpt pasted into the prompt.
    // The ingestion Lambda indexes each uploaded file as one document, so this must be
    // large enough to hold a whole log file or the model never sees the later events.
    private static final int MAX_EXCERPT_CHARS = 20_000;

    private final ForensicSearchService searchService;
    private final BedrockRuntimeAsyncClient bedrockClient;
    private final String modelId;

    public ForensicRagService(
            ForensicSearchService searchService,
            BedrockRuntimeAsyncClient bedrockClient,
            @Value("${aws.bedrock.model-id}") String modelId) {
        this.searchService = searchService;
        this.bedrockClient = bedrockClient;
        this.modelId = modelId;
    }

    /**
     * Executes the full RAG pipeline and streams tokens to {@code consumer}.
     *
     * <p>The method returns a {@link CompletableFuture} that completes when the
     * last token has been delivered (or completes exceptionally with a
     * {@link ForensicChatException} if any stage fails).</p>
     *
     * @param request  validated chat request from the controller
     * @param consumer callback invoked for every token delta from the model
     * @return a future that resolves when streaming finishes
     */
    public CompletableFuture<Void> streamAnalysis(
            ForensicChatRequest request,
            StreamTokenConsumer consumer) {

        log.info("RAG pipeline start — caseId={} query='{}'",
                request.caseId(), request.query());

        // --- Retrieve -----------------------------------------------------------
        return searchService
                .searchAsync(new ForensicSearchRequest(request.caseId(), request.query()))
                .thenCompose(searchResponse -> {

                    List<ForensicHit> hits = searchResponse.hits().stream()
                            .limit(MAX_CONTEXT_HITS)
                            .toList();

                    log.info("RAG retrieve — caseId={} hitsUsed={} totalHits={}",
                            request.caseId(), hits.size(), searchResponse.totalHits());

                    // --- Augment ------------------------------------------------
                    String systemPrompt = buildSystemPrompt(request.caseId(), hits);
                    String userMessage  = request.query();

                    // --- Generate (stream) --------------------------------------
                    return invokeBedrockStream(
                            request.caseId(), systemPrompt, userMessage, consumer);
                })
                .exceptionally(ex -> {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    log.error("RAG pipeline failed — caseId={}", request.caseId(), cause);
                    throw new ForensicChatException(
                            "RAG analysis failed for caseId=" + request.caseId(), cause);
                });
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Builds a structured system prompt that instructs the model to act as a
     * fraud-forensic analyst, scoped to the evidence excerpts retrieved from
     * OpenSearch for the given case.
     */
    private String buildSystemPrompt(String caseId, List<ForensicHit> hits) {
        StringBuilder sb = new StringBuilder(2048);
        sb.append("You are an expert fraud-forensic analyst. ");
        sb.append("Answer the user's question using ONLY the evidence excerpts below. ");
        sb.append("If an excerpt is insufficient, say so explicitly. ");
        sb.append("Do not speculate beyond the provided evidence.\n\n");
        sb.append("CASE ID: ").append(caseId).append("\n\n");
        sb.append("EVIDENCE EXCERPTS (").append(hits.size()).append(" documents):\n");

        for (int i = 0; i < hits.size(); i++) {
            ForensicHit hit = hits.get(i);
            String excerpt = hit.excerpt();
            if (excerpt.length() > MAX_EXCERPT_CHARS) {
                excerpt = excerpt.substring(0, MAX_EXCERPT_CHARS) + " [truncated]";
            }
            sb.append("\n[").append(i + 1).append("] ")
              .append("documentId=").append(hit.documentId())
              .append(" s3Key=").append(hit.s3Key())
              .append(" score=").append(String.format("%.4f", hit.score()))
              .append("\n").append(excerpt).append("\n");
        }

        return sb.toString();
    }

    /**
     * Calls {@code BedrockRuntimeAsyncClient.converseStream} and pipes every
     * text delta to {@code consumer} on the virtual thread that the AWS SDK
     * event-stream handler runs on.
     *
     * @return a {@link CompletableFuture} that completes when the stream closes
     */
    private CompletableFuture<Void> invokeBedrockStream(
            String caseId,
            String systemPrompt,
            String userMessage,
            StreamTokenConsumer consumer) {

        Message userMsg = Message.builder()
                .role(ConversationRole.USER)
                .content(ContentBlock.fromText(userMessage))
                .build();

        ConverseStreamRequest converseRequest = ConverseStreamRequest.builder()
                .modelId(modelId)
                .system(s -> s.text(systemPrompt))
                .messages(userMsg)
                .build();

        ConverseStreamResponseHandler responseHandler = ConverseStreamResponseHandler.builder()
                .subscriber(ConverseStreamResponseHandler.Visitor.builder()
                        .onContentBlockDelta(delta -> {
                            if (delta.delta().text() != null) {
                                consumer.accept(delta.delta().text());
                            }
                        })
                        .build())
                .onError(ex -> log.error(
                        "Bedrock stream error — caseId={}", caseId, ex))
                .build();

        log.info("Bedrock ConverseStream invocation — caseId={} modelId={}", caseId, modelId);
        return bedrockClient.converseStream(converseRequest, responseHandler);
    }
}
