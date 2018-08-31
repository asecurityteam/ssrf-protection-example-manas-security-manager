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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;

import java.awt.GraphicsEnvironment;
import java.io.File;
import java.util.logging.Logger;

/**
 * Helper class to add default security permission.
 *
 * @author Meder Kydyraliev
 */
public class DefaultSecurityRules {

    // @VisibleForTesting static Supplier<String[]> defaultFontPathProvider = new SunFontPathSupplier();

    private static final Logger logger = Logger.getLogger(DefaultSecurityRules.class.getName());

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
    }

    private static void addMiscPermissions(SecurityPolicy policy) {
        // AWT determines Linux distribution by attempting to read various /etc/*-release files
        policy.addPath("/etc/*", java.awt.GraphicsEnvironment.class.getName(), FileOperation.READ);
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

    private static void addContainerSpecificPermissions(SecurityPolicy policy) {
        // TODO(meder): Add this.
    }

    // TODO(meder): Unfortunately, this is the best way to get the name of the class
    @SuppressWarnings("sunapi")
    private static String getGraphicsEnvironmentClassName() {
        return sun.java2d.SunGraphicsEnvironment.class.getName();
    }

}