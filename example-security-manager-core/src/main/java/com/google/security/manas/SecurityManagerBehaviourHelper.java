package com.google.security.manas;

import java.security.Security;
import java.util.concurrent.ForkJoinPool;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Helper class to assist in changing the behaviour of java to be closer to when
 * a security manager is not in effect.
 */
public class SecurityManagerBehaviourHelper {

    private static final Logger logger = Logger.getLogger(
            SecurityManagerBehaviourHelper.class.getName());


    private static final String CACHE_POLICY_PROPERTY_NAME = "networkaddress.cache.ttl";
    private static final String NIO_THREAD_POOL_THREAD_FACTORY_NAME = "java.nio.channels.DefaultThreadPool.threadFactory";
    private static final String THREAD_FACTORY_NAME = "java.util.concurrent.ForkJoinPool.common.threadFactory";


    /**
     * Specify a networkaddress.cache.ttl value if one is not already specified.
     * The {@link sun.net.InetAddressCachePolicy} policy is to cache forever
     * when the security manager is present unless the property
     * networkaddress.cache.ttl specifies otherwise.
     */
    public void setUpInetAddressCachePolicy() {
        if (Security.getProperty(CACHE_POLICY_PROPERTY_NAME) == null) {
            Security.setProperty(CACHE_POLICY_PROPERTY_NAME, "30");
        }
    }

    /**
     * Specify a fork join worker thread factory if one is not already
     * specified. ParallelStream uses InnocuousForkJoinWorkerThread by default
     * when the security manager is present unless the property
     * java.util.concurrent.ForkJoinPool.common.threadFactory specifies
     * otherwise. InnocuousForkJoinWorkerThread throws SecurityExceptions in
     * setContextClassLoader so we need to force it to use
     * DefaultForkJoinWorkerThreadFactory instead.
     */
    public void setUpForkJoinWorkerThreadFactory() {
        if (System.getProperty(THREAD_FACTORY_NAME) == null) {
            // We have to refer to DefaultForkJoinWorkerThreadFactory this way
            // to avoid having makeCommonPool called prior to setting the system
            // property here.
            System.setProperty(THREAD_FACTORY_NAME,
                    "java.util.concurrent.ForkJoinPool$DefaultForkJoinWorkerThreadFactory");
        }
        logger.log(Level.INFO, "ForkJoinPool thread factory class is " +
                ForkJoinPool.commonPool().getFactory().getClass());
    }

    /**
     * Specify a nio default thread factory if one is not already specified.
     * {@link sun.nio.ch.ThreadPool} uses InnocuousThread by default when the
     * security manager is present unless the property java.nio.channels.DefaultThreadPool.threadFactory
     * specifies otherwise. InnocuousThread can throw a SecurityException in
     * setContextClassLoader so need to force the use of {@link
     * DefaultNIOThreadFactory}.
     */
    public void setUpNIOThreadFactory() {
        if (System.getProperty(NIO_THREAD_POOL_THREAD_FACTORY_NAME) == null) {
            System.setProperty(NIO_THREAD_POOL_THREAD_FACTORY_NAME,
                    DefaultNIOThreadFactory.class.getName());
            logger.log(Level.INFO, "Set the default NIO thread factory class to " +
                    DefaultNIOThreadFactory.class.getName());
        }
    }
}
