package com.google.security.manas;

import com.google.security.manas.test.ManasExecutionMixin;
import com.google.security.test.SocketConnector;
import org.junit.Test;

import java.io.IOException;

public class SocketConnectionExecutionTest extends ManasExecutionMixin {
    @Test
    public void testNotPermittedSocketConnectionIsBlocked() throws IOException, InterruptedException {
        final String expectedErrorMessage = "Security policy violation: (\"java.net.SocketPermission\" \"169.254.169.254\" \"connect,resolve\")";
        final Process process = runtime.exec(generateCommand(
                SocketConnector.class.getCanonicalName(),
                "example-amazon-metadata.properties"));
        assertBlocked(process, expectedErrorMessage);
    }
}
