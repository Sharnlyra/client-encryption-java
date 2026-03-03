package com.mastercard.developer.crypto.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * TLS/SSL configuration using JCE SSLContext API.
 * Includes trust-all TrustManager (weak — for policy testing).
 */
public class TlsConfiguration {

    public SSLContext createDefaultTlsContext() throws NoSuchAlgorithmException {
        return SSLContext.getInstance("TLS");
    }

    public SSLContext createTls12Context() throws NoSuchAlgorithmException {
        return SSLContext.getInstance("TLSv1.2");
    }

    public SSLContext createTls13Context() throws NoSuchAlgorithmException {
        return SSLContext.getInstance("TLSv1.3");
    }

    /**
     * Dynamic protocol — crypto-finder must trace the parameter.
     */
    public SSLContext createContextForProtocol(String protocol) throws NoSuchAlgorithmException {
        return SSLContext.getInstance(protocol);
    }

    public SSLContext createMutualTlsContext(KeyStore keyStore, char[] keyPassword,
                                             KeyStore trustStore)
            throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    /**
     * Weak: Trust-all TrustManager — accepts any certificate.
     * This is a deliberate policy violation for scanner testing.
     */
    public SSLContext createTrustAllContext()
            throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // intentionally empty — trust all
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // intentionally empty — trust all
                    }
                }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAll, new SecureRandom());
        return sslContext;
    }

    public KeyStore loadKeyStore(InputStream stream, char[] password, String type)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(stream, password);
        return keyStore;
    }
}
