package com.mastercard.developer.crypto.service;

import com.mastercard.developer.crypto.thirdparty.ApacheHttpClientCrypto;
import com.mastercard.developer.crypto.thirdparty.OkHttpCrypto;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * Top-level crypto service orchestrator.
 * Never touches JCE directly — all crypto is delegated to CryptoMiddleware or Layer 2 classes.
 * This creates 4-level call chains for crypto-finder to trace.
 *
 * Example: CryptoService → CryptoMiddleware → KeyDerivationOperations → SecretKeyFactory.getInstance(...)
 */
public class CryptoService {

    private final CryptoMiddleware middleware = new CryptoMiddleware();
    private final ApacheHttpClientCrypto apacheHttp = new ApacheHttpClientCrypto();
    private final OkHttpCrypto okHttp = new OkHttpCrypto();

    /**
     * 4-level chain: CryptoService → CryptoMiddleware → HmacOperations → Mac.getInstance("HmacSHA256")
     */
    public byte[] authenticateMessage(byte[] key, byte[] message) throws Exception {
        return middleware.computeHmac(key, message);
    }

    /**
     * 4-level weak chain: CryptoService → CryptoMiddleware → HmacOperations → Mac.getInstance("HmacMD5")
     */
    public byte[] authenticateMessageLegacy(byte[] key, byte[] message) throws Exception {
        return middleware.computeLegacyHmac(key, message);
    }

    /**
     * Dynamic dispatch through 4 levels.
     */
    public byte[] authenticateMessageDynamic(String mode, byte[] key, byte[] message)
            throws Exception {
        return middleware.computeHmacDynamic(mode, key, message);
    }

    /**
     * 4-level chain: CryptoService → CryptoMiddleware → SignatureOperations → Signature.getInstance(...)
     */
    public byte[] signPayload(PrivateKey privateKey, byte[] payload) throws Exception {
        return middleware.signData(privateKey, payload);
    }

    public byte[] signPayloadEcdsa(PrivateKey privateKey, byte[] payload) throws Exception {
        return middleware.signDataEcdsa(privateKey, payload);
    }

    /**
     * 4-level chain: CryptoService → CryptoMiddleware → KeyDerivationOperations → SecretKeyFactory.getInstance(...)
     */
    public SecretKey deriveEncryptionKey(char[] password, byte[] salt) throws Exception {
        return middleware.deriveKey(password, salt);
    }

    public KeyPair generateSigningKeyPair() throws Exception {
        return middleware.generateRsaKeyPair();
    }

    public KeyPair generateEcSigningKeyPair() throws Exception {
        return middleware.generateEcKeyPair();
    }

    /**
     * 3-level chain via Commons Codec: CryptoService → CryptoMiddleware → CommonsCodecCrypto → DigestUtils
     */
    public String computeChecksum(byte[] data) {
        return middleware.hashData(data);
    }

    /**
     * Weak: MD5 hash buried 3 levels deep.
     */
    public String computeChecksumLegacy(byte[] data) {
        return middleware.hashDataLegacy(data);
    }

    /**
     * BouncyCastle chain: CryptoService → CryptoMiddleware → BouncyCastleCrypto → SHA3Digest
     */
    public byte[] computeSha3Hash(byte[] data) {
        return middleware.hashSha3(data);
    }

    public byte[] computeBlake2bHash(byte[] data) {
        return middleware.hashBlake2b(data);
    }

    /**
     * TLS via middleware: CryptoService → CryptoMiddleware → TlsConfiguration → SSLContext.getInstance(...)
     */
    public SSLContext getSecureTlsContext() throws Exception {
        return middleware.createSecureTlsContext();
    }

    /**
     * HTTP client chains — 3-level chain via Apache HttpClient.
     * CryptoService → ApacheHttpClientCrypto → SSLContextBuilder
     */
    public Object createSecureHttpClient(java.security.KeyStore trustStore) throws Exception {
        return apacheHttp.createClientWithTrustStore(trustStore);
    }

    /**
     * Weak: Trust self-signed via Apache HttpClient — 3-level chain.
     */
    public Object createLegacyHttpClient(java.security.KeyStore trustStore) throws Exception {
        return apacheHttp.createClientTrustingSelfSigned(trustStore);
    }

    /**
     * OkHttp with certificate pinning — 2-level chain.
     */
    public Object createPinnedOkHttpClient(String hostname, String pin) {
        return okHttp.createPinnedClient(hostname, pin);
    }

    /**
     * Weak: OkHttp trust-all — 3-level chain via TlsConfiguration.
     */
    public Object createTrustAllOkHttpClient() throws Exception {
        return okHttp.createTrustAllClient();
    }
}
