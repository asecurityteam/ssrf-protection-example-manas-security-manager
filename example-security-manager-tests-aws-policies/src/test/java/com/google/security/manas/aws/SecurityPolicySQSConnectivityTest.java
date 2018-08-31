package com.google.security.manas.aws;

import com.google.security.manas.test.aws.SQSSecurityManagerMixin;
import org.junit.Test;

import java.io.IOException;

public class SecurityPolicySQSConnectivityTest extends SQSSecurityManagerMixin {

    @Test
    public void testExampleAmazonMetadataPermittedToAwsMetadataResource()
            throws IOException, InterruptedException {
        assertPermittedConnectToAwsMetadataResource(
                "example-amazon-metadata.properties");
    }
}
