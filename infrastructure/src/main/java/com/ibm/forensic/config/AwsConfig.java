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

    @Value("${aws.region:ap-south-1}")
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
     */
    @Bean
    public OpenSearchClient openSearchClient() {
        var httpClient = ApacheHttpClient.builder().build();

        // Fix: Safely clean the endpoint string to extract ONLY the raw host domain name
        String cleanedEndpoint = openSearchEndpoint
                .replace("https://", "")
                .replace("http://", "")
                .replace("/", "")
                .trim();

        // Strip out trailing slash paths if present
        if (cleanedEndpoint.contains("/")) {
            cleanedEndpoint = cleanedEndpoint.split("/")[0];
        }

        AwsSdk2Transport transport = new AwsSdk2Transport(
                httpClient,
                cleanedEndpoint, // Passes the pure host domain to prevent NullPointer/Host exceptions
                "aoss",          // Service name for OpenSearch Serverless
                Region.of(awsRegion),
                AwsSdk2TransportOptions.builder()
                        .setCredentials(DefaultCredentialsProvider.create())
                        .build());

        return new OpenSearchClient(transport);
    }
}
