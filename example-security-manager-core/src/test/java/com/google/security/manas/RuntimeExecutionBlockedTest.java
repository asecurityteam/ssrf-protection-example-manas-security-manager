package com.google.security.manas;

import com.google.security.test.RuntimeExecutor;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertThat;

public class RuntimeExecutionBlockedTest extends com.google.security.manas.ManasExecutionMixin {
    @Test
    public void testNotPermittedRuntimeExecutionIsBlocked() throws IOException, InterruptedException {
        final String expectedErrorMessage = "(\"java.io.FilePermission\" \"echo\" \"execute\")";
        final Process process = runtime.exec(generateCommand(
                RuntimeExecutor.class.getCanonicalName(), null));
        String errorOutput = assertBlocked(process, expectedErrorMessage);
        assertThat(errorOutput, not(containsString("command-argument")));
    }

}
