package com.google.security.manas.test.aws;

import com.amazonaws.SdkClientException;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.AmazonSQSException;
import com.google.security.manas.ManasSecurityManager;

import java.net.SocketTimeoutException;

public class SQSWithInstanceCredentialsUse {
    private static final String NON_EXISTING_QUEUE_NAME =
            "non-existing-54ed0419952c46c3840084a141ec5fa2621544e8";

    public static void main(String[] args) {
        System.setSecurityManager(ManasSecurityManager.getInstance());
        try {
            InstanceProfileCredentialsProvider credentials =
                    InstanceProfileCredentialsProvider.getInstance();
            AmazonSQSClientBuilder builder = AmazonSQSClient.builder();
            builder.setCredentials(credentials);
            builder.setRegion("us-east-1");
            AmazonSQS client = builder.build();
            client.getQueueUrl(NON_EXISTING_QUEUE_NAME);
        } catch (AmazonSQSException e) {
            // expected.
        } catch (SdkClientException e) {
            if (!e.getCause().getClass().equals(SocketTimeoutException.class)) {
                throw new RuntimeException();
            }
        }
    }
}
