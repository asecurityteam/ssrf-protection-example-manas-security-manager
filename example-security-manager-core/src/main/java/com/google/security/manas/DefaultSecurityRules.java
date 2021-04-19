/*
 * Copyright (C) 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.security.manas;

import com.google.common.base.Preconditions;
import sun.security.util.SecurityConstants;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Helper class to add default security permission.
 *
 * @author Meder Kydyraliev
 */
public class DefaultSecurityRules {

    // @VisibleForTesting static Supplier<String[]> defaultFontPathProvider = new SunFontPathSupplier();

    private static final Logger logger = Logger.getLogger(DefaultSecurityRules.class.getName());
    private static final String CONFIG_FILE_PROPERTY = "manas.policyfile";
    private static final String KEY_CLASSES_ALLOWED_TO_CONNECT_TO_AWS_METADATA =
            "class.permitted.to.connect.to.aws.metadata.resource";

    private DefaultSecurityRules() {
    }

    /**
     * Add default set of permissions for a typical Java web app.
     *
     * @param policy to add permissions to.
     */
    public static void addDefaultRules(SecurityPolicy policy) {
        addJreDirsPermission(policy);
        addTempDirsPermissions(policy);
        addDevicePermissions(policy);
        addContainerSpecificPermissions(policy);
        addMiscPermissions(policy);
        addMavenRepositoryDirectoryReadOnly(policy);
        loadProperties(policy);
    }

    private static void addMiscPermissions(SecurityPolicy policy) {
        // AWT determines Linux distribution by attempting to read various /etc/*-release files
        policy.addPath("/etc/*", java.awt.GraphicsEnvironment.class.getName(), FileOperation.READ);
        // java cacerts
        policy.addPath("/etc/ssl/certs/java/cacerts", FileOperation.READ);
    }

    private static void addDevicePermissions(SecurityPolicy policy) {
        // write privileges are needed to mix random data into the entropy
        // pool by java.security.SecureRandom.setSeed()
        policy.addPath("/dev/random", FileOperation.READ, FileOperation.WRITE);
        policy.addPath("/dev/urandom", FileOperation.READ, FileOperation.WRITE);
        policy.addPath("/dev/null", FileOperation.READ, FileOperation.WRITE);
    }

    private static void addJreDirsPermission(SecurityPolicy policy) {
        String javaHome = System.getProperty("java.home");
        Preconditions.checkNotNull(javaHome);
        policy.addPath(Utility.makePathRecursive(javaHome), FileOperation.READ);

        String bootClassPath = System.getProperty("sun.boot.class.path");
        if (bootClassPath != null) {
            for (String path : Utility.separatePathsAndMakeRecursive(bootClassPath))
                policy.addPath(path, FileOperation.READ);
        }

        String javaLibraryPaths = System.getProperty("java.library.path");
        if (javaLibraryPaths != null) {
            for (String path : Utility.separatePathsAndMakeRecursive(javaLibraryPaths)) {
                policy.addPath(path, FileOperation.READ);
            }
        }
    }

    private static void addTempDirsPermissions(SecurityPolicy policy) {
        String tmpDir = System.getenv("java.io.tmpdir");
        if (tmpDir != null) {
            policy.addPath(Utility.makePathRecursive(tmpDir),
                    FileOperation.READ, FileOperation.WRITE, FileOperation.DELETE);
        }
        policy.addPath("/tmp/-", FileOperation.READ, FileOperation.WRITE, FileOperation.DELETE);
        // just /tmp since some code checks for existence and write permissions
        policy.addPath("/tmp", FileOperation.READ, FileOperation.WRITE);
    }

    private static void addMavenRepositoryDirectoryReadOnly(SecurityPolicy policy) {
        final String userHome = System.getProperty("user.home");
        if (userHome == null || userHome.equals("")) {
            return;
        }
        String mavenDir = userHome + "/.m2/repository/-";
        policy.addPath(mavenDir, FileOperation.READ);
    }

    private static void addContainerSpecificPermissions(SecurityPolicy policy) {
        policy.addPath("/proc/self/mountinfo", FileOperation.READ);
        policy.addPath("/proc/self/cgroup", FileOperation.READ);
        policy.addPath("/sys/fs/cgroup/memory/*", FileOperation.READ);
    }

    // TODO(meder): Unfortunately, this is the best way to get the name of the class
    @SuppressWarnings("sunapi")
    private static String getGraphicsEnvironmentClassName() {
        return sun.java2d.SunGraphicsEnvironment.class.getName();
    }

    private static void addAwsMetadataClassesToPolicy(
            Set<String> awsMetadataClasses, SecurityPolicy policy) {
        final String socketPermissions = SecurityConstants.SOCKET_CONNECT_ACCEPT_ACTION +
                "," + SecurityConstants.SOCKET_LISTEN_ACTION +
                "," + SecurityConstants.SOCKET_RESOLVE_ACTION;
        final String awsMetadataHost = "169.254.169.254";
        for (String clazz : awsMetadataClasses) {
            if (!clazz.trim().isEmpty()) {
                policy.addSocket(awsMetadataHost, clazz, socketPermissions);
            }
        }
    }

    private static void loadProperties(SecurityPolicy policy) {
        final Properties config = new Properties();
        String configFile = System.getProperty(CONFIG_FILE_PROPERTY);
        if (configFile == null) {
            return;
        }
        final InputStream in = DefaultSecurityRules.class.getResourceAsStream(
                configFile);
        if (in == null) {
            throw new RuntimeException(
                    "Failed to load Manas configuration properties from: " +
                            configFile);
        }
        try {
            config.load(in);
            in.close();
        } catch (IOException e) {
            throw new RuntimeException(
                    "Failed to load Manas configuration properties from:" +
                            configFile + " " + e.getMessage());
        }
        final Set<String> classesAllowedToAwsMeta = Utility.getProperty(
                config, KEY_CLASSES_ALLOWED_TO_CONNECT_TO_AWS_METADATA);
        if (classesAllowedToAwsMeta != null) {
            addAwsMetadataClassesToPolicy(classesAllowedToAwsMeta, policy);
        }
    }
}
