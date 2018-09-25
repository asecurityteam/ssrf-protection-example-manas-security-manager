package com.google.security.manas;

import java.util.concurrent.ThreadFactory;

/**
 * Copy of the default ThreadFactory code used in {@link sun.nio.ch.ThreadPool}
 * when no security manager is active.
 */
public class DefaultNIOThreadFactory implements ThreadFactory {

    @Override
    public Thread newThread(Runnable r) {
        Thread t = new Thread(r);
        t.setDaemon(true);
        return t;
    }
}
