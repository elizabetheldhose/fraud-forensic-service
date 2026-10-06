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
 */
@EnableAsync
@SpringBootApplication
public class FraudForensicApplication {

    public static void main(String[] args) {
        SpringApplication.run(FraudForensicApplication.class, args);
    }

    @Bean
    public TomcatProtocolHandlerCustomizer<?> virtualThreadTomcatCustomizer() {
        return protocolHandler ->
                protocolHandler.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
    }

    @Bean
    public AsyncTaskExecutor applicationTaskExecutor() {
        return new TaskExecutorAdapter(Executors.newVirtualThreadPerTaskExecutor());
    }
}
