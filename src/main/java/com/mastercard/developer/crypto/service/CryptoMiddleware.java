package com.mastercard.developer.crypto.service;

import com.mastercard.developer.crypto.commons.CommonsCodecCrypto;
import com.mastercard.developer.crypto.hmac.HmacOperations;
import com.mastercard.developer.crypto.keyderivation.KeyDerivationOperations;
import com.mastercard.developer.crypto.signature.SignatureOperations;
import com.mastercard.developer.crypto.thirdparty.BouncyCastleCrypto;
import com.mastercard.developer.crypto.tls.TlsConfiguration;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Mid-level crypto middleware — wraps Layer 3 operations.
 * Contains buried weak-algo calls and conditional dispatch.
 * Layer 1 — depends on all Layer 3 classes.
 */
public class CryptoMiddleware {

    private final HmacOperations hmacOps = new HmacOperations();
    private final SignatureOperations signatureOps = new SignatureOperations();
    private final KeyDerivationOperations keyDerivOps = new KeyDerivationOperations();
    private final CommonsCodecCrypto commonsCodec = new CommonsCodecCrypto();
    private final BouncyCastleCrypto bcCrypto = new BouncyCastleCrypto();
    private final TlsConfiguration tlsConfig = new TlsConfiguration();

    /**
     * 3-level chain: CryptoMiddleware → HmacOperations → Mac.getInstance("HmacSHA256")
     */
    public byte[] computeHmac(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacOps.computeHmacSha256(key, data);
    }

    /**
     * Weak: Buried HmacMD5 call — 3-level chain through HmacOperations.
     */
    public byte[] computeLegacyHmac(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacOps.computeHmacMd5(key, data);
    }

    /**
     * Conditional dispatch — algorithm determined at runtime.
     */
    public byte[] computeHmacDynamic(String algorithm, byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        if ("legacy".equals(algorithm)) {
            return hmacOps.computeHmacMd5(key, data);
        } else if ("sha512".equals(algorithm)) {
            return hmacOps.computeHmacSha512(key, data);
        } else {
            return hmacOps.computeHmacSha256(key, data);
        }
    }

    /**
     * 3-level chain: CryptoMiddleware → SignatureOperations → Signature.getInstance("SHA256withRSA")
     */
    public byte[] signData(PrivateKey privateKey, byte[] data) throws Exception {
        return signatureOps.signWithRsa(privateKey, data);
    }

    public byte[] signDataEcdsa(PrivateKey privateKey, byte[] data) throws Exception {
        return signatureOps.signWithEcdsa(privateKey, data);
    }

    /**
     * 3-level chain: CryptoMiddleware → KeyDerivationOperations → SecretKeyFactory.getInstance(...)
     */
    public SecretKey deriveKey(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return keyDerivOps.deriveKeyPbkdf2Sha256(password, salt, 310000, 256);
    }

    public KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        return keyDerivOps.generateRsaKeyPair(2048);
    }

    public KeyPair generateEcKeyPair() throws Exception {
        return keyDerivOps.generateEcKeyPair("secp256r1");
    }

    /**
     * Commons Codec chain: CryptoMiddleware → CommonsCodecCrypto → DigestUtils.sha256Hex
     */
    public String hashData(byte[] data) {
        return commonsCodec.sha256Hex(data);
    }

    /**
     * Weak: MD5 hash buried 2 levels deep.
     */
    public String hashDataLegacy(byte[] data) {
        return commonsCodec.md5Hex(data);
    }

    /**
     * BouncyCastle chain: CryptoMiddleware → BouncyCastleCrypto → SHA3Digest
     */
    public byte[] hashSha3(byte[] data) {
        return bcCrypto.sha3_256(data);
    }

    public byte[] hashBlake2b(byte[] data) {
        return bcCrypto.blake2b256(data);
    }

    /**
     * TLS context chain: CryptoMiddleware → TlsConfiguration → SSLContext.getInstance(...)
     */
    public javax.net.ssl.SSLContext createSecureTlsContext() throws NoSuchAlgorithmException {
        return tlsConfig.createTls13Context();
    }
}
