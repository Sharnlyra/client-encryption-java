package com.mastercard.developer.crypto.thirdparty;

import com.mastercard.developer.crypto.tls.TlsConfiguration;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;

/**
 * Apache HttpClient SSL/TLS configuration.
 * Exercises SSLContextBuilder, TrustSelfSignedStrategy, and TrustAll patterns.
 * Layer 2 — depends on TlsConfiguration (Layer 3).
 */
public class ApacheHttpClientCrypto {

    private final TlsConfiguration tlsConfig = new TlsConfiguration();

    /**
     * Creates an HTTP client with custom truststore via Apache's SSLContextBuilder.
     */
    public CloseableHttpClient createClientWithTrustStore(KeyStore trustStore)
        throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(trustStore, null)
            .build();
        SSLConnectionSocketFactory socketFactory =
            new SSLConnectionSocketFactory(sslContext);
        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }

    /**
     * Weak: Trusts self-signed certificates.
     */
    public CloseableHttpClient createClientTrustingSelfSigned(
        KeyStore trustStore
    ) throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(trustStore, TrustSelfSignedStrategy.INSTANCE)
            .build();
        SSLConnectionSocketFactory socketFactory =
            new SSLConnectionSocketFactory(sslContext);
        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }

    /**
     * Weak: Trust-all strategy — accepts any certificate.
     */
    public CloseableHttpClient createClientTrustingAll() throws Exception {
        TrustStrategy trustAll = new TrustStrategy() {
            public boolean isTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
                return true;
            }
        };
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(null, trustAll)
            .build();
        SSLConnectionSocketFactory socketFactory =
            new SSLConnectionSocketFactory(sslContext);
        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }

    /**
     * Uses SSLContexts.custom() builder — another Apache SSL entry point.
     */
    public CloseableHttpClient createClientWithCustomSsl(
        KeyStore keyStore,
        char[] keyPassword,
        KeyStore trustStore
    ) throws Exception {
        SSLContext sslContext = SSLContexts.custom()
            .loadKeyMaterial(keyStore, keyPassword)
            .loadTrustMaterial(trustStore, null)
            .build();
        SSLConnectionSocketFactory socketFactory =
            new SSLConnectionSocketFactory(sslContext);
        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }

    /**
     * Chain through TlsConfiguration (Layer 3) — creates a 2-level call chain.
     */
    public CloseableHttpClient createClientViaTlsConfig() throws Exception {
        SSLContext sslContext = tlsConfig.createTls12Context();
        SSLConnectionSocketFactory socketFactory =
            new SSLConnectionSocketFactory(sslContext);
        return HttpClients.custom().setSSLSocketFactory(socketFactory).build();
    }
}
