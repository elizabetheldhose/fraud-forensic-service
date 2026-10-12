package com.ibm.forensic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatProtocolHandlerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.core.task.support.TaskExecutorAdapter;
import org.springframework.scheduling.annotation.EnableAsync;

import java.util.concurrent.Executors;

/**
 * Entry point for the AI Fraud Forensic backend service.
 *
 * <p>Virtual Threads (JEP 444 / Java 21) are enabled for both Tomcat's
 * request-handling thread pool and the Spring {@code @Async} executor, so that
 * all I/O-bound work (S3, SQS, OpenSearch) blocks cheaply instead of
 * consuming platform threads.</p>
 */
@EnableAsync
@SpringBootApplication
public class FraudForensicApplication {

    public static void main(String[] args) {
        SpringApplication.run(FraudForensicApplication.class, args);
    }

    /**
     * Replace Tomcat's platform-thread executor with a Virtual Thread executor.
     * Each incoming HTTP request is handled on its own lightweight virtual thread.
     */
    @Bean
    public TomcatProtocolHandlerCustomizer<?> virtualThreadTomcatCustomizer() {
        return protocolHandler ->
                protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    /**
     * Default {@code @Async} executor — backs all {@link org.springframework.scheduling.annotation.Async}
     * method calls with a virtual-thread-per-task executor.
     *
     * <p>Named {@code "applicationTaskExecutor"} so Spring Boot picks it up as the
     * default MVC async executor as well.</p>
     */
    @Bean
    public AsyncTaskExecutor applicationTaskExecutor() {
        return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
    }
}
