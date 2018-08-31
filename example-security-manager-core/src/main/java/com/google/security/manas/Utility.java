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

import com.google.common.collect.ImmutableSet;

import java.util.Properties;
import java.util.Set;

/**
 * Utility class for ManasSecurityManager
 *
 * @author Meder Kydyraliev
 */
public class Utility {

    private static final String DELIMITER_REGEX = "\\s+";

    private Utility() {
    }

    public static String makePathRecursive(String path) {
        if (!path.endsWith("/-")) {
            path = path.endsWith("/") ? path + "-" : path + "/-";
        }
        return path;
    }

    public static String[] separatePathsAndMakeRecursive(String paths) {
        String[] rawPaths = paths.split(System.getProperty("path.separator"));
        for (int k = 0; k < rawPaths.length; k++) {
            if (!rawPaths[k].endsWith(".jar")) {
                rawPaths[k] = Utility.makePathRecursive(rawPaths[k]);
            }
        }
        return rawPaths;
    }

    /**
     * Checks if currently installed security manager is the singleton instance of the ManasSecurityManager.
     *
     * @return {@code true} if ManasSecurityManager was already installed, {@code false} otherwise.
     */
    public static boolean isManasSecurityManagerAlreadyInstalled() {
        SecurityManager currentManager = System.getSecurityManager();
        if (currentManager == null) {
            return false;
        }
        if (currentManager instanceof ManasSecurityManager) {
            if (currentManager == ManasSecurityManager.getInstance()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns a set of strings matching the given key found in the properties
     * provided separated by DELIMITER_REGEX.
     *
     * @param config the given properties instance
     * @param key the key to retrieve the property from
     * @return a set of strings matching the given key found in the properties
     * provided separated by DELIMITER_REGEX.
     */
    public static Set<String> getProperty(Properties config, final String key) {
        String value = config.getProperty(key);
        if (value != null && !value.equals("")) {
            return ImmutableSet.copyOf(value.trim().split(DELIMITER_REGEX));
        }
        return null;
    }
}
