package com.google.security.manas.test;

import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import org.hamcrest.core.StringContains;
import org.junit.Before;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public abstract class ManasExecutionMixin {
    public Runtime runtime;

    @Before
    public void setUp() throws Exception {
        runtime = Runtime.getRuntime();
    }

    public String[] generateCommand(String clazz, String policyFileName) {
        ArrayList<String> parts = new ArrayList<>();
        parts.add("java");
        if (policyFileName != null) {
            parts.add("-Dmanas.policyfile=" + policyFileName);
        }
        if (System.getProperty("java.version").compareTo("1.9") >= 0) {
            parts.add("--add-exports=java.base/jdk.internal.reflect=ALL-UNNAMED");
        }
        parts.add("-classpath");
        parts.add(System.getProperty("java.class.path") +
                System.getProperty("sun.boot.class.path"));
        parts.add(clazz);
        return parts.toArray(new String[0]);
    }

    public String assertNotBlocked(Process process, String expectedOutput)
            throws InterruptedException, IOException {
        String errorOutput = checkStdErrOutput(process, expectedOutput);
        String message = " 0 != " + process.exitValue() + " - " + errorOutput;
        assertEquals(message, 0, process.exitValue());
        return errorOutput;
    }

    public String assertBlocked(Process process, String expectedErrorMessage) throws IOException, InterruptedException {
        String errorOutput = checkStdErrOutput(process, expectedErrorMessage);
        assertEquals(1, process.exitValue());
        return errorOutput;
    }

    private String checkStdErrOutput(Process process, String expectedOutput)
            throws IOException, InterruptedException {
        process.waitFor();
        String errorOutput = readStream(process.getErrorStream());
        assertThat(errorOutput, StringContains.containsString(expectedOutput));
        return errorOutput;
    }

    public String readStream(InputStream is) throws IOException {
        String result = CharStreams.toString(new InputStreamReader(
                is, Charsets.UTF_8));
        is.close();
        return result;
    }

}
