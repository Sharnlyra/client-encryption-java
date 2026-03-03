package com.mastercard.developer.crypto.keyderivation;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

/**
 * Key derivation and key pair generation operations.
 * Covers PBKDF2 variants and asymmetric key generation (RSA, EC, DH).
 */
public class KeyDerivationOperations {

    public SecretKey deriveKeyPbkdf2Sha256(char[] password, byte[] salt, int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        return factory.generateSecret(spec);
    }

    public SecretKey deriveKeyPbkdf2Sha512(char[] password, byte[] salt, int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        return factory.generateSecret(spec);
    }

    public KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public KeyPair generateEcKeyPair(String curveName)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        generator.initialize(ecSpec);
        return generator.generateKeyPair();
    }

    public KeyPair generateDhKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }
}
