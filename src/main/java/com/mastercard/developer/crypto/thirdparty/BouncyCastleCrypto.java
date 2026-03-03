package com.mastercard.developer.crypto.thirdparty;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * BouncyCastle crypto operations — both low-level BC API and JCE with BC provider.
 * Tests detection of non-JCE crypto (SHA3Digest, Blake2bDigest, Ed25519Signer)
 * and explicit provider selection (Cipher.getInstance("...", "BC")).
 */
public class BouncyCastleCrypto {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * BC low-level API — no JCE getInstance call.
     */
    public byte[] sha3_256(byte[] data) {
        SHA3Digest digest = new SHA3Digest(256);
        digest.update(data, 0, data.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    /**
     * BC low-level API — BLAKE2b.
     */
    public byte[] blake2b256(byte[] data) {
        Blake2bDigest digest = new Blake2bDigest(256);
        digest.update(data, 0, data.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    /**
     * BC low-level API — Ed25519 key generation.
     */
    public AsymmetricCipherKeyPair generateEd25519KeyPair() {
        Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
        generator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return generator.generateKeyPair();
    }

    /**
     * BC low-level API — Ed25519 signing.
     */
    public byte[] signEd25519(AsymmetricCipherKeyPair keyPair, byte[] message) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, keyPair.getPrivate());
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    /**
     * BC low-level API — X25519 key generation.
     */
    public AsymmetricCipherKeyPair generateX25519KeyPair() {
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(new SecureRandom()));
        return generator.generateKeyPair();
    }

    /**
     * JCE with explicit BC provider — ChaCha20.
     */
    public byte[] encryptChaCha20(SecretKey key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("ChaCha20", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    /**
     * JCE with explicit BC provider — AES-SIV (nonce-misuse resistant).
     */
    public byte[] encryptAesSiv(SecretKey key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/SIV/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    /**
     * JCE MessageDigest with explicit BC provider.
     */
    public byte[] sha3_256ViaJce(byte[] data)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256", "BC");
        return digest.digest(data);
    }

    /**
     * Generate a ChaCha20 key via JCE with BC provider.
     */
    public SecretKey generateChaCha20Key() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("ChaCha20", "BC");
        keyGen.init(256);
        return keyGen.generateKey();
    }
}
