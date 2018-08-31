package com.google.security.manas;

import com.google.common.collect.ImmutableSet;
import org.junit.Before;
import org.junit.Test;
import sun.security.util.SecurityConstants;

import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class DefaultSecurityRulesTest {
    private static final String CONFIG_FILE_PROPERTY = "manas.policyfile";

    private static final Set<String> EXPECTED_CLOUD_AWS_META_CLASSES = ImmutableSet.of(
            "com.amazonaws.http.AmazonHttpClient",
            "com.amazonaws.internal.ConnectionUtils",
            "com.amazonaws.internal.EC2MetadataClient",
            "com.amazonaws.http.",
            "com.amazonaws.internal."
    );

    @Before
    public void setUp() throws Exception {
        System.clearProperty(CONFIG_FILE_PROPERTY);
    }

    @Test
    public void testEmptyPropertiesLoad() {
        SecurityPolicy mockedSecurityPolicy = mock(SecurityPolicy.class);
        DefaultSecurityRules.addDefaultRules(mockedSecurityPolicy);
    }

    @Test
    public void testExampleAmazonMetadata() {
        assertPropertiesLoadedCorrectly(
                "example-amazon-metadata.properties",
                EXPECTED_CLOUD_AWS_META_CLASSES
        );
    }

    @Test(expected = RuntimeException.class)
    public void testMissingPropertiesFileLoad() throws Exception {
        System.setProperty(CONFIG_FILE_PROPERTY, "doesnotexist.properties");
        SecurityPolicy mockedSecurityPolicy = mock(SecurityPolicy.class);
        DefaultSecurityRules.addDefaultRules(mockedSecurityPolicy);
    }

    public void assertPropertiesLoadedCorrectly(
            String policy,
            Set<String> permittedAwsMetaClasses) {
        System.setProperty(CONFIG_FILE_PROPERTY, policy);
        SecurityPolicy mockedSecurityPolicy = mock(SecurityPolicy.class);
        DefaultSecurityRules.addDefaultRules(mockedSecurityPolicy);
        for (String clazz : permittedAwsMetaClasses) {
            verify(mockedSecurityPolicy).addSocket("169.254.169.254", clazz,
                    SecurityConstants.SOCKET_CONNECT_ACCEPT_ACTION +
                            "," + SecurityConstants.SOCKET_LISTEN_ACTION +
                            "," + SecurityConstants.SOCKET_RESOLVE_ACTION);
        }
    }

}