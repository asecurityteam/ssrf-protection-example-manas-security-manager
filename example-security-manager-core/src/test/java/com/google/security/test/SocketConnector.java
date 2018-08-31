package com.google.security.test;

import com.google.security.manas.ManasSecurityManager;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

public class SocketConnector {
    public static void main(String args[]) throws IOException, ReflectiveOperationException {
        System.setSecurityManager(ManasSecurityManager.getInstance());
        connectToAwsMetadataResource();
    }

    public static void connectToAwsMetadataResource() throws IOException {
        URL url = new URL("http://169.254.169.254");
        URLConnection conn = url.openConnection();
        conn.connect();
    }
}
