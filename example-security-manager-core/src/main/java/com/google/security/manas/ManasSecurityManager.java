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
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Sets;
import com.google.common.net.InetAddresses;
import sun.security.util.SecurityConstants;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FilePermission;
import java.lang.reflect.Member;
import java.net.InetAddress;
import java.net.SocketPermission;
import java.net.UnknownHostException;
import java.security.Permission;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Security manager that restricts permissions of an application running under it. We overwrite checkPermission()
 * methods and return immediately, which ensures that permissions that we currently do not care about aren't enforced.
 * Specific permissions are enforced by overriding corresponding checkXXX() methods.
 *
 * @author Meder Kydyraliev
 */
public final class ManasSecurityManager extends SecurityManager implements SecurityPolicy {

    // If true, the security manager will throw exception on violations instead of logging them
    @VisibleForTesting
    boolean throwOnError = true;

    private final List<com.google.security.manas.SecurityViolationReporter> reporters =
            new CopyOnWriteArrayList<com.google.security.manas.SecurityViolationReporter>();

    // The singleton instance of Manas Security Manager.
    private static ManasSecurityManager instance = null;

    private static final String AWS_META_HOST = "169.254.169.254";

    private static final Logger logger = Logger.getLogger(ManasSecurityManager.class.getName());

    private static final String LOGGING_MODE_PROPERTY_NAME = "manas.insecure";
    private static final String LOG_CHECK_CONNECT_NAME = "manas.log.checkconnect";
    private static final String LOG_CHECK_CONNECT_STACK_NAME = "manas.log.checkconnect.stack";
    private static final String LOG_CHECK_CONNECT_INTERNAL_ONLY_NAME = "manas.log.checkconnect.internalonly";

    private LoadingCache<InetAddress, Set<String>> addressToDnsCache =
            CacheBuilder.newBuilder().maximumSize(1000).build(
                    new CacheLoader<InetAddress, Set<String>>()
                    {
                        @Override
                        public Set<String> load(InetAddress inetAddress)
                        {
                            return Sets.newConcurrentHashSet();
                        }
                    }
            );

    @VisibleForTesting
    boolean denyManagerUninstallation = true;

    private final SecurityManagerPermissions perms = new SecurityManagerPermissions();
    private static final String java_lang_System_name = java.lang.System.class.getName();
    private static final String manas_package_name =
            ManasSecurityManager.class.getPackage().getName();

    // variable used to detect recursive permission checking calls
    private final ThreadLocal<Boolean> inCheck = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return Boolean.FALSE;
        }
    };

    private boolean logCheckConnectCalls;
    private boolean logCheckConnectCallsStack;
    private boolean logCheckConnectCallsInternalOnly;


    private ManasSecurityManager() {
        if (System.getProperty(LOGGING_MODE_PROPERTY_NAME) != null) {
            throwOnError = false;
        }
        logCheckConnectCalls = Boolean.getBoolean(LOG_CHECK_CONNECT_NAME);
        logCheckConnectCallsStack = Boolean.getBoolean(LOG_CHECK_CONNECT_STACK_NAME);
        logCheckConnectCallsInternalOnly = Boolean.getBoolean(LOG_CHECK_CONNECT_INTERNAL_ONLY_NAME);
        addReporter(new LoggingViolationReporter());
        if (throwOnError) {
            logger.log(Level.INFO, "SecurityException will be thrown on security policy violations");
        }
    }

    /**
     * Returns the singleton instance of Google Security Manager.
     */
    public static synchronized ManasSecurityManager getInstance() {
        if (instance == null) {
            SecurityManagerBehaviourHelper behaviourHelper =
                    new SecurityManagerBehaviourHelper();
            behaviourHelper.setUpInetAddressCachePolicy();
            behaviourHelper.setUpForkJoinWorkerThreadFactory();
            behaviourHelper.setUpNIOThreadFactory();
            logger.log(Level.INFO, "Creating Manas Java Security Manager");
            instance = new ManasSecurityManager();
            DefaultSecurityRules.addDefaultRules(instance);
            instance.lock();
        }
        return instance;
    }

    @VisibleForTesting
    ManasSecurityManager(SecurityViolationReporter... reporters) {
        Preconditions.checkArgument(reporters.length > 0);
        this.reporters.addAll(Arrays.asList(reporters));
    }

    /**
     * Add security policy violation reporter.
     *
     * @param reporter to report security violations to.
     * @throws NullPointerException if {@code reporter} is {@code null}.
     */
    public void addReporter(SecurityViolationReporter reporter) {
        Preconditions.checkNotNull(reporter);
        reporters.add(reporter);
    }

    @Override
    public void checkExec(String cmd) {
        FilePermission perm = new FilePermission(cmd, FileOperation.EXEC.getName());
        checkGenericPermission(perm);
    }

    @Override
    public void checkRead(String file) {
        FilePermission perm = new FilePermission(file, FileOperation.READ.getName());
        checkGenericPermission(perm);
    }

    @Override
    public void checkRead(String file, Object context) {
        FilePermission perm = new FilePermission(file, FileOperation.READ.getName());
        checkGenericPermission(perm);
    }

    @Override
    public void checkWrite(String file) {
        FilePermission perm = new FilePermission(file, FileOperation.WRITE.getName());
        checkGenericPermission(perm);
    }

    @Override
    public void checkDelete(String file) {
        FilePermission perm = new FilePermission(file, FileOperation.DELETE.getName());
        checkGenericPermission(perm);
    }

    /**
     * Locks the security manager. Any attempts to modify the state of the security manager, for example, by calling
     * {@link #addPath(String, com.google.security.manas.FileOperation...)}, will result in an {@code
     * IllegalStateException} being thrown by that thread.
     *
     * @throws IllegalStateException if security manager is already locked.
     */
    public void lock() {
        perms.lock();
    }

    private void checkGenericPermission(Permission perm) {
        if (!isAllowed(perm)) {
            if (shouldIgnoreViolation(perm)) {
                return;
            }
            for (SecurityViolationReporter reporter : reporters) {
                reporter.reportViolation(perm);
            }
            if (throwOnError) {
                throw new SecurityException("Permission denied:" + perm);
            }
        }
    }

    private boolean shouldIgnoreViolation(Permission perm) {
        if (perm instanceof FilePermission) {
            // recursive call due to the exists() check below
            if (isCheckRecursive()) {
                return true;
            }
            try {
                inCheck.set(Boolean.TRUE);
                // This optimization allows read access to files that do not exist, which
                // is harmless and usually denotes innocent file presence checks.
                if (FileOperation.READ.getName().equals(perm.getActions())) {
                    return !new File(perm.getName()).exists();
                }
            } finally {
                inCheck.set(Boolean.FALSE);
            }
        }
        return false;
    }

    private boolean isCheckRecursive() {
        return inCheck.get().equals(Boolean.TRUE);
    }

    private boolean isAllowed(Permission perm) {
        return perms.implies(perm);
    }

    private void disallowSecurityManagerInstallation(Permission perm) {
        if (denyManagerUninstallation && perm instanceof RuntimePermission) {
            // Disallow installation of any other security managers
            if ("setSecurityManager".equals(perm.getName())) {
                throw new SecurityException("Another security manager cannot be installed");
            }
        }
    }

    private void maybeThrowExceptionIfAllFiles(String path) {
        // <<ALL FILES>> is a constant used by FilePermission to denote all files
        if ("<<ALL FILES>>".equalsIgnoreCase(path) ||
                "/-".equalsIgnoreCase(path)) {
            throw new IllegalArgumentException("Adding access to all files is disallowed."
                    + "Supplied path: " + path);
        }
    }

    /**
     * Add path with the specified permissions to the security policy enforced by the Google Java Security Manager.
     *
     * @param path path to a file or directory. See {@link java.io.FilePermission} for supported path wildcards.
     * @param permissions one or more permissions to be allowed on the specified path.
     * @throws NullPointerException if any argument is {@code null}.
     * @throws IllegalArgumentException if permissions is empty
     * @throws IllegalStateException if manager was locked by calling {@link #lock()}.
     */
    @Override
    public void addPath(String path, FileOperation... permissions) {
        Preconditions.checkNotNull(path);
        Preconditions.checkNotNull(permissions);
        Preconditions.checkArgument(permissions.length > 0);
        maybeThrowExceptionIfAllFiles(path);

        logger.log(Level.INFO, "Adding permissions: path=" + path + " permissions=" +
                Arrays.toString(permissions));
        for (FileOperation permission : permissions) {
            perms.add(new FilePermission(path, permission.getName()));
        }
    }

    /**
     * Add path with the specified permissions to the security policy enforced by the Google Java Security Manager.
     *
     * @param path path to a file or directory. See {@link java.io.FilePermission} for supported path wildcards.
     * @param authorizedClass Class to assign the specified file permissions to. This security manager will check for
     * presence of the specified class on the execution stack. This class needs to be as specific as possible (i.e.
     * don't assign sensitive permissions to your main class, instead specify the class that's actually performing the
     * operation on the specified path).
     * @param permissions one or more permissions to be allowed on the specified path.
     * @throws NullPointerException if any argument is {@code null}
     * @throws IllegalArgumentException if permissions is empty
     * @throws IllegalStateException if manager was locked by calling {@link #lock()}.
     */
    @Override
    public void addPath(String path, String authorizedClass, FileOperation... permissions) {
        Preconditions.checkNotNull(path);
        Preconditions.checkNotNull(authorizedClass);
        Preconditions.checkNotNull(permissions);
        Preconditions.checkArgument(permissions.length > 0);
        maybeThrowExceptionIfAllFiles(path);

        logger.log(Level.INFO, "Adding permissions: path=" + path + " authorized_class=" +
                authorizedClass + " permissions=" + Arrays.toString(permissions));
        for (FileOperation permission : permissions) {
            perms.add(new FilePermission(path, permission.getName()), authorizedClass);
        }
    }

    /**
     * Add path with the specified permissions to the security policy enforced by the Google Java Security Manager.
     *
     * @param path path to a file or directory. See {@link java.io.FilePermission} for supported path wildcards.
     * @param authorizedClass Class to assign the specified permissions to. Security manager will check for presence of
     * the specified class on the execution stack. This class needs to be as specific as possible (i.e. don't assign
     * sensitive permissions to your main class, instead specify the class that's actually performing the operation on
     * the specified path).
     * @param permissions one or more permissions to be allowed on the specified path.
     * @throws IllegalStateException if security manager wasn't enabled via command line argument.
     */
    public void addPath(String path, Class authorizedClass, FileOperation... permissions) {
        Preconditions.checkNotNull(path);
        Preconditions.checkNotNull(authorizedClass);
        Preconditions.checkArgument(permissions.length > 0);
        maybeThrowExceptionIfAllFiles(path);
        addPath(path, authorizedClass.getName(), permissions);
    }

    public void addSocket(String host, String authorizedClass, String socketPermissions) {
        logger.log(Level.INFO, "Adding permissions: host=" + host +
                " authorizedClass=" + authorizedClass + " " +
                socketPermissions);
        perms.add(new SocketPermission(host, socketPermissions), authorizedClass);
    }

    @Override
    public void checkPermission(Permission perm) {
        disallowSecurityManagerInstallation(perm);
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        disallowSecurityManagerInstallation(perm);
    }

    public void checkMemberAccess(Class<?> clazz, int which) {
        // disallow access to private members of java.lang.System, since it is
        // possible to obtain java.lang.System's "security" using reflection and
        // set the field to null thus disabling security manager.
        // additionally disallow access to private members of any of the classes
        // in this package.
        String errorMessage = null;

        if (which != Member.PUBLIC && java_lang_System_name.equalsIgnoreCase(clazz.getName())) {
            errorMessage = "MANAS Security violation: access to " +
                    "non-public java.lang.System members disallowed.";
        } else if (clazz.getPackage() != null && manas_package_name.equalsIgnoreCase(clazz.getPackage().getName())) {
            errorMessage = "MANAS Security violation: access to members in " +
                    this.getClass().getPackage().getName() + " package is disallowed.";
        }
        if (errorMessage != null) {
            logger.log(Level.SEVERE, errorMessage, new Throwable());
            if (throwOnError) {
                throw new SecurityException(errorMessage);
            }
        }
    }

    @Override
    public void checkRead(FileDescriptor fd) {
        // TODO(meder): see if this is ever called and in what context
    }

    @Override
    public void checkWrite(FileDescriptor fd) {
        // TODO(meder): see if this is ever called and in what context
    }

    // NB(meder) All of the methods below are overridden for performance reasons.
    // They return immediately to save an extra call to checkPermission() and
    // construction of permission objects.
    @Override
    public void checkCreateClassLoader() {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkAccess(Thread t) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkAccess(ThreadGroup g) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkExit(int status) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkLink(String lib) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkConnect(String host, int port) {
        checkConnect(host, port, null);
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        if (port != -1 && AWS_META_HOST.equals(host) &&
                perms.permissionsForPermissionClass(SocketPermission.class) != null) {
            checkGenericPermission(new SocketPermission(host,
                    SecurityConstants.SOCKET_CONNECT_ACTION));
        }
        if (logCheckConnectCalls && !isCheckRecursive()) {
            try {
                inCheck.set(Boolean.TRUE);
                logCheckConnect(host, port);
                inCheck.set(Boolean.FALSE);
            } finally {
                inCheck.set(Boolean.FALSE);
            }
        }
    }

    /**
     * Fill in the cache of addresses -> name for the given name.
     */
    private void cacheAddressForName(String host) throws UnknownHostException {
        for (InetAddress address : InetAddress.getAllByName(host)) {
            if (!logCheckConnectCallsInternalOnly || Utility.isAPrivateAddress(address)) {
                Set<String> hosts = addressToDnsCache.getUnchecked(address);
                if (!hosts.contains(host)) {
                    if (hosts.size() >= 10) {
                        logger.warning("Not adding host entry cache for " +
                                Utility.formatIPAddressForLog(address.getHostAddress()) +
                                        " " + host);
                    } else {
                        hosts.add(host);
                    }
                }
            }
        }
    }

    private void logCheckConnect(String host, int port) {
        Throwable throwable = null;
        if (logCheckConnectCallsStack) {
            throwable = new Throwable();
        }
        if (!InetAddresses.isInetAddress(host)) {
            try {
                cacheAddressForName(host);
            } catch (UnknownHostException e) {
            }
        } else {
            try {
                InetAddress inetAddress = InetAddress.getByName(host);
                if (!logCheckConnectCallsInternalOnly ||
                        (!Utility.isAPrivateAddress(inetAddress) && logCheckConnectCallsInternalOnly)
                ) {
                    final String ipForLog = Utility.formatIPAddressForLog(host);
                    SortedSet<String> hosts = new TreeSet<>();
                    hosts.addAll(addressToDnsCache.asMap().getOrDefault(inetAddress,
                            new TreeSet<>()));
                    logger.log(Level.INFO, "checkConnect ip: " +
                            ipForLog + ":" + port + " (" + hosts + ")", throwable);
                }
            } catch (UnknownHostException e) {
            }
        }
    }


    @Override
    public void checkListen(int port) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkAccept(String host, int port) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkMulticast(InetAddress maddr) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkPropertiesAccess() {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkPropertyAccess(String key) {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkPrintJobAccess() {
        // permission is allowed. Overriden for performance reasons.
    }

    public void checkSystemClipboardAccess() {
        // permission is allowed. Overriden for performance reasons.
    }

    public void checkAwtEventQueueAccess() {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkPackageDefinition(String pkg) {
        if (pkg.startsWith("com.google.security.manas")) {
            checkPermission(
                    new RuntimePermission("defineClassInPackage." + pkg));
        }
    }

    @Override
    public void checkPackageAccess(String pkg) {
        super.checkPackageAccess(pkg);
        if (pkg.startsWith("com.google.security.manas")) {
            checkPermission(
                    new RuntimePermission("defineClassInPackage." + pkg));
        }
    }

    @Override
    public void checkSetFactory() {
        // permission is allowed. Overriden for performance reasons.
    }

    @Override
    public void checkSecurityAccess(String target) {
        // permission is allowed. Overriden for performance reasons.
    }
}
