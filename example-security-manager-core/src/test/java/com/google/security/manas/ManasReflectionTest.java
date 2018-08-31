package com.google.security.manas;

import org.junit.Test;
import org.mockito.Mock;

import java.lang.reflect.Member;

public class ManasReflectionTest {
    @Mock
    SecurityViolationReporter securityViolationReporter;

    @Test
    public void testReflectionAccessToJavaLangSystemPublicMember() {
        ManasSecurityManager manas = new ManasSecurityManager(securityViolationReporter);
        manas.checkMemberAccess(System.class, Member.PUBLIC);
    }

    @Test(expected = java.lang.SecurityException.class)
    public void testReflectionAccessToJavaLangSystemDeclaredMember() {
        ManasSecurityManager manas = new ManasSecurityManager(securityViolationReporter);
        manas.checkMemberAccess(System.class, Member.DECLARED);
    }

    @Test
    public void testReflectionAccessToJavaLangSystemDeclaredMemberInLoggingMode() {
        ManasSecurityManager manas = new ManasSecurityManager(securityViolationReporter);
        manas.throwOnError = false;
        manas.checkMemberAccess(System.class, Member.DECLARED);
    }

    @Test(expected = java.lang.SecurityException.class)
    public void testReflectionAccessToManas() {
        ManasSecurityManager manas = new ManasSecurityManager(securityViolationReporter);
        manas.checkMemberAccess(ManasSecurityManager.class, Member.DECLARED);
    }

    @Test
    public void testReflectionAccessToManasInLoggingMode() {
        ManasSecurityManager manas = new ManasSecurityManager(securityViolationReporter);
        manas.throwOnError = false;
        manas.checkMemberAccess(ManasSecurityManager.class, Member.DECLARED);
    }

}
