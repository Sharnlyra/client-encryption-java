package com.mastercard.developer.crypto.service;

import com.mastercard.developer.crypto.thirdparty.ApacheHttpClientCrypto;
import com.mastercard.developer.crypto.thirdparty.OkHttpCrypto;
import java.security.KeyPair;
import java.security.PrivateKey;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;

/**
 * Top-level crypto service orchestrator.
 * Never touches JCE directly — all crypto is delegated to CryptoMiddleware or Layer 2 classes.
 * This creates 4-level call chains for crypto-finder to trace.
 *
 * Example: CryptoService → CryptoMiddleware → KeyDerivationOperations → SecretKeyFactory.getInstance(...)
 */
public class CryptoService {

    private final CryptoMiddleware middleware = new CryptoMiddleware();
    private final ApacheHttpClientCrypto apacheHttp =
        new ApacheHttpClientCrypto();
    private final OkHttpCrypto okHttp = new OkHttpCrypto();

    /**
     * 4-level chain: CryptoService → CryptoMiddleware → HmacOperations → Mac.getInstance("HmacSHA256")
     */
    public byte[] authenticateMessage(byte[] key, byte[] message)
        throws Exception {
        return middleware.computeHmac(key, message);
    }

    /**
     * 4-level weak chain: CryptoService → CryptoMiddleware → HmacOperations → Mac.getInstance("HmacMD5")
     */
    public byte[] authenticateMessageLegacy(byte[] key, byte[] message)
        throws Exception {
        return middleware.computeLegacyHmac(key, message);
    }

    /**
     * Dynamic dispatch through 4 levels.
     */
    public byte[] authenticateMessageDynamic(
        String mode,
        byte[] key,
        byte[] message
    ) throws Exception {
        return middleware.computeHmacDynamic(mode, key, message);
    }

    /**
     * 4-level chain: CryptoService → CryptoMiddleware → SignatureOperations → Signature.getInstance(...)
     */
    public byte[] signPayload(PrivateKey privateKey, byte[] payload)
        throws Exception {
        return middleware.signData(privateKey, payload);
    }

    public byte[] signPayloadEcdsa(PrivateKey privateKey, byte[] payload)
        throws Exception {
        return middleware.signDataEcdsa(privateKey, payload);
    }

    /**
     * 4-level chain: CryptoService → CryptoMiddleware → KeyDerivationOperations → SecretKeyFactory.getInstance(...)
     */
    public SecretKey deriveEncryptionKey(char[] password, byte[] salt)
        throws Exception {
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
    public byte[] computeSha3Hash(byte[] sha3Data) {
        return middleware.hashSha3(sha3Data);
    }

    public byte[] computeBlake2bHash(byte[] blake2HashData) {
        return middleware.hashBlake2b(blake2HashData);
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
    public Object createSecureHttpClient(java.security.KeyStore trustStore)
        throws Exception {
        return apacheHttp.createClientWithTrustStore(trustStore);
    }

    /**
     * DEPENDENCY SCANNING — 4-level chain ending in JCA calls inside bcpkix JAR.
     *
     * CryptoService → CryptoMiddleware → BouncyCastlePkixCrypto
     *   → JceOpenSSLPKCS8EncryptorBuilder.build()  [bcpkix JAR]
     *     → Cipher.getInstance("AES/CBC/...")       [JCA — found by semgrep in the JAR]
     */
    public byte[] encryptPrivateKey(
        java.security.PrivateKey key,
        char[] password
    ) throws Exception {
        return middleware.encryptPrivateKey(key, password);
    }

    /**
     * CryptoService → CryptoMiddleware → BouncyCastlePkixCrypto
     *   → JceOpenSSLPKCS8DecryptorProviderBuilder.build()  [bcpkix JAR]
     *     → Cipher.getInstance(...)                         [JCA — found by semgrep in the JAR]
     */
    public java.security.PrivateKey decryptPrivateKey(
        byte[] encryptedPkcs8,
        char[] password
    ) throws Exception {
        return middleware.decryptPrivateKey(encryptedPkcs8, password);
    }

    /**
     * CryptoService → CryptoMiddleware → BouncyCastlePkixCrypto
     *   → JcaPEMKeyConverter.getKeyPair()            [bcpkix JAR]
     *     → KeyFactory.getInstance("RSA"/"ECDSA")    [JCA — found by semgrep in the JAR]
     */
    public KeyPair convertPemKeyPair(String pem) throws Exception {
        return middleware.convertPemKeyPair(pem);
    }

    /**
     * CryptoService → CryptoMiddleware → BouncyCastlePkixCrypto
     *   → JcaX509CertificateConverter.getCertificate()       [bcpkix JAR]
     *     → CertificateFactory.getInstance("X.509")           [JCA — found by semgrep in the JAR]
     */
    public java.security.cert.X509Certificate parsePemCertificate(String pem)
        throws Exception {
        return middleware.parsePemCertificate(pem);
    }

    public String exportToPem(Object cryptoObject) throws Exception {
        return middleware.exportToPem(cryptoObject);
    }

    /**
     * Weak: Trust self-signed via Apache HttpClient — 3-level chain.
     */
    public Object createLegacyHttpClient(java.security.KeyStore trustStore)
        throws Exception {
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
