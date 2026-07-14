package com.github.intoolswetrust.jsignpdf.pades;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;

import org.junit.jupiter.api.Test;

/**
 * Tests the port TSA basic-auth credentials are registered against. {@link URI#getPort()} returns -1 for a URL
 * that omits the port, and credentials registered against port -1 are never sent — so a TSA URL without an
 * explicit port has to fall back to the scheme's default port, or basic authentication silently does nothing
 * and the TSA answers 401.
 */
public class TsaAuthPortTest {

    @Test
    public void testExplicitPortIsUsedAsGiven() {
        assertEquals(8080, SignerLogic.resolvePort(URI.create("http://tsa.example.com:8080/tsr")));
        assertEquals(8443, SignerLogic.resolvePort(URI.create("https://tsa.example.com:8443/tsr")));
    }

    @Test
    public void testMissingPortFallsBackToTheSchemeDefault() {
        assertEquals(443, SignerLogic.resolvePort(URI.create("https://tsa.example.com/tsr")));
        assertEquals(80, SignerLogic.resolvePort(URI.create("http://tsa.example.com/tsr")));
    }
}
