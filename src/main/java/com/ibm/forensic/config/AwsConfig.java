package com.ibm.forensic.config;

import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.transport.aws.AwsSdk2Transport;
import org.opensearch.client.transport.aws.AwsSdk2TransportOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.sqs.SqsClient;

/**
 * AWS SDK v2 client configuration.
 *
 * <p>Credentials are resolved automatically via the {@link DefaultCredentialsProvider}
 * chain (env vars → system props → IAM role → ~/.aws/credentials).
 * No credentials are hard-coded here — see security policy section 4.</p>
 */
@Configuration
public class AwsConfig {

    @Value("${aws.region:us-east-1}")
    private String awsRegion;

    @Value("${aws.opensearch.endpoint}")
    private String openSearchEndpoint;

    @Bean
    public S3Client s3Client() {
        return S3Client.builder()
                .region(Region.of(awsRegion))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    @Bean
    public S3Presigner s3Presigner() {
        return S3Presigner.builder()
                .region(Region.of(awsRegion))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    @Bean
    public SqsClient sqsClient() {
        return SqsClient.builder()
                .region(Region.of(awsRegion))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }

    /**
     * High-level OpenSearch client backed by AWS SigV4 transport.
     *
     * <p>The {@link AwsSdk2Transport} wraps an {@link ApacheHttpClient} and signs
     * every HTTP request with SigV4 using the same {@link DefaultCredentialsProvider}
     * chain as the other AWS clients.  For OpenSearch <em>Serverless</em> the
     * service name must be {@code "aoss"}; for a managed OpenSearch domain use
     * {@code "es"} instead.</p>
     *
     * <p>TLS is enforced by the HTTPS endpoint URI — the Apache HTTP client
     * validates the server certificate against the JVM trust store by default.</p>
     */
    @Bean
    public OpenSearchClient openSearchClient() {
        var httpClient = ApacheHttpClient.builder().build();

        AwsSdk2Transport transport = new AwsSdk2Transport(
                httpClient,
                openSearchEndpoint,
                "aoss",   // service name for OpenSearch Serverless; use "es" for managed domains
                Region.of(awsRegion),
                AwsSdk2TransportOptions.builder()
                        .setCredentials(DefaultCredentialsProvider.create())
                        .build());

        return new OpenSearchClient(transport);
    }
}
