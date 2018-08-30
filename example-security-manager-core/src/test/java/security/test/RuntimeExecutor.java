package com.google.security.test;

import com.google.security.manas.ManasSecurityManager;

import java.io.IOException;

public class RuntimeExecutor {
    public static void main(String args[]) throws IOException, ReflectiveOperationException {
        System.setSecurityManager(ManasSecurityManager.getInstance());
        // Test execution.
        Runtime.getRuntime().exec("echo command-argument");
    }
}
