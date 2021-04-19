package com.google.security.test;

import com.google.security.manas.DefaultNIOThreadFactory;
import com.google.security.manas.ManasSecurityManager;
import sun.net.InetAddressCachePolicy;
import sun.nio.ch.ThreadPool;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ThreadFactory;

public class RuntimeExecutor {
    public static void main(String args[]) throws IOException, ReflectiveOperationException {
        System.setSecurityManager(ManasSecurityManager.getInstance());
        testsetUpInetAddressCachePolicy();
        testSetUpForkJoinWorkerThreadFactory();
        testSetUpNIOThreadFactory();
        testModifySecurityManagerProperties();
        // Test execution.
        Runtime.getRuntime().exec("echo command-argument");
    }

    public static void testModifySecurityManagerProperties() throws IllegalAccessException {
        try {
            Security.setProperty("package.access", ".");
            throw new RuntimeException("Was able to modify package.access");
        }
        catch (java.lang.SecurityException e) {}
        try {
            Class clazz = ManasSecurityManager.getInstance().getClass();
            Field field = clazz.getDeclaredField("throwOnError");
            field.setAccessible(true);
            field.set(ManasSecurityManager.getInstance(), false);
            throw new RuntimeException("Was able to modify throwOnError");
        }
        catch (NoSuchFieldException e) {}
    }

    public static void testsetUpInetAddressCachePolicy() {
        String cache = Security.getProperty("networkaddress.cache.ttl");
        if (!"30".equals(cache) || InetAddressCachePolicy.get() != 30) {
            throw new RuntimeException(
                    "Incorrect value for networkaddress.cache.ttl " +
                            cache + " " +
                            "InetAddressCachePolicy.get() = " +
                            InetAddressCachePolicy.get());
        }
    }

    public static void testSetUpForkJoinWorkerThreadFactory()
            throws ReflectiveOperationException {
        // Test that the ForkJoinPool thread factory is correctly setup.
        ForkJoinPool pool = ForkJoinPool.commonPool();
        Class clazz = Class.forName(
                "java.util.concurrent.ForkJoinPool$DefaultForkJoinWorkerThreadFactory");
        if (!pool.getFactory().getClass().equals(clazz)) {
            throw new RuntimeException("Incorrect ForkJoinWorkerThreadFactory. " +
                    pool.getFactory().getClass());
        }
    }

    public static void testSetUpNIOThreadFactory() throws ReflectiveOperationException {
        // Test that the ThreadPool thread factory is correctly setup.
        Method m = ThreadPool.class.getDeclaredMethod("getDefault");
        m.setAccessible(true);
        ThreadPool threadPool = (ThreadPool) m.invoke(null, null);

        Field executorField = threadPool.getClass().getDeclaredField("executor");
        executorField.setAccessible(true);
        ExecutorService executor = (ExecutorService) executorField.get(threadPool);
        Field threadFactoryField = executor.getClass().getDeclaredField(
                "threadFactory");
        threadFactoryField.setAccessible(true);
        ThreadFactory threadFactory = (ThreadFactory) threadFactoryField.get(executor);
        if (!threadFactory.getClass().equals(DefaultNIOThreadFactory.class)) {
            throw new RuntimeException("Incorrect NIO ThreadPool. " +
                    threadFactory.getClass());
        }
    }
}
