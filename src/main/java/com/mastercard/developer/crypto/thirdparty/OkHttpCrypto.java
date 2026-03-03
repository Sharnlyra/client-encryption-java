package com.mastercard.developer.crypto.thirdparty;

import com.mastercard.developer.crypto.tls.TlsConfiguration;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * OkHttp SSL/TLS configuration.
 * Exercises CertificatePinner, custom SSLSocketFactory, and trust-all patterns.
 * Layer 2 — depends on TlsConfiguration (Layer 3).
 */
public class OkHttpCrypto {

    private final TlsConfiguration tlsConfig = new TlsConfiguration();

    /**
     * Certificate pinning via OkHttp's CertificatePinner.
     */
    public OkHttpClient createPinnedClient(String hostname, String sha256Pin) {
        CertificatePinner pinner = new CertificatePinner.Builder()
                .add(hostname, "sha256/" + sha256Pin)
                .build();
        return new OkHttpClient.Builder()
                .certificatePinner(pinner)
                .build();
    }

    /**
     * Custom SSL via TlsConfiguration chain — 2-level call chain to SSLContext.
     */
    public OkHttpClient createClientWithTls12() throws Exception {
        SSLContext sslContext = tlsConfig.createTls12Context();
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        // Need a trust manager for OkHttp
        X509TrustManager trustManager = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        };

        return new OkHttpClient.Builder()
                .sslSocketFactory(socketFactory, trustManager)
                .build();
    }

    /**
     * Weak: Trust-all via TlsConfiguration's trustAllContext — 2-level weak chain.
     */
    public OkHttpClient createTrustAllClient()
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = tlsConfig.createTrustAllContext();
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        X509TrustManager trustAll = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        };

        return new OkHttpClient.Builder()
                .sslSocketFactory(socketFactory, trustAll)
                .build();
    }

    /**
     * Dynamic protocol via TlsConfiguration — crypto-finder must trace the parameter.
     */
    public OkHttpClient createClientWithProtocol(String protocol) throws Exception {
        SSLContext sslContext = tlsConfig.createContextForProtocol(protocol);
        sslContext.init(null, null, new SecureRandom());
        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        X509TrustManager trustManager = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        };

        return new OkHttpClient.Builder()
                .sslSocketFactory(socketFactory, trustManager)
                .build();
    }
}
