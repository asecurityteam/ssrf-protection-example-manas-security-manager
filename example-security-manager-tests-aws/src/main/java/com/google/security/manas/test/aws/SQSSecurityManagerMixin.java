package com.google.security.manas.test.aws;


import com.google.security.manas.test.ManasExecutionMixin;

import java.io.IOException;

public class SQSSecurityManagerMixin extends ManasExecutionMixin {

    public void assertPermittedConnectToAwsMetadataResource(String policyName)
            throws IOException, InterruptedException {
        String[] cmd = generateCommand(
                SQSWithInstanceCredentialsUse.class.getCanonicalName(),
                policyName);
        final Process process = runtime.exec(cmd);
        assertNotBlocked(process, "Manas Java Security Manager");
    }
}
