package com.google.security.manas;


import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UtilityTest {

    @Test
    public void publicIPv4Address() throws UnknownHostException {
        assertFalse(Utility.isAPrivateAddress(
                InetAddress.getByName("198.51.100.1")));
    }

    @Test
    public void publicIPv6Address() throws UnknownHostException {
        assertFalse(Utility.isAPrivateAddress(
                InetAddress.getByName("2001:db8::1")));
    }

    @Test
    public void privateIPv4Address() throws UnknownHostException {
        assertTrue(Utility.isAPrivateAddress(
                InetAddress.getByName("10.0.0.1")));
    }

    @Test
    public void privateIPv6Address() throws UnknownHostException {
        assertTrue(Utility.isAPrivateAddress(
                InetAddress.getByName("::1")));
    }

    @Test
    public void formatIpAddressForLogIPv4() {
        final String ipAddress = "10.0.0.1";
        assertEquals(ipAddress, Utility.formatIPAddressForLog(ipAddress));
    }

    @Test
    public void formatIpAddressForLogIPv6() {
        final String ipAddress = "0:0:0:0:0:0:0:1";
        final String expected = "[" + ipAddress + "]";
        assertEquals(expected, Utility.formatIPAddressForLog(ipAddress));
    }

}
