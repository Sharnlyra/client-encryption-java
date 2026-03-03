package com.mastercard.developer.crypto.signature;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Digital signature operations using JCE Signature API.
 * Covers RSA, ECDSA, and RSA-PSS algorithms.
 */
public class SignatureOperations {

    public byte[] signWithRsa(PrivateKey privateKey, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public boolean verifyWithRsa(PublicKey publicKey, byte[] data, byte[] signatureBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public byte[] signWithEcdsa(PrivateKey privateKey, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public boolean verifyWithEcdsa(PublicKey publicKey, byte[] data, byte[] signatureBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public byte[] signWithRsaPss(PrivateKey privateKey, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException,
                   InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        PSSParameterSpec pssSpec = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        signature.setParameter(pssSpec);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Dynamic algorithm — crypto-finder must trace the parameter.
     */
    public byte[] signWithAlgorithm(String algorithm, PrivateKey privateKey, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}
