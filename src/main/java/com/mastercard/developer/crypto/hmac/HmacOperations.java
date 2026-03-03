package com.mastercard.developer.crypto.hmac;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * HMAC operations using both JCE and Commons Codec.
 * Exercises Mac.getInstance with multiple algorithms and dynamic dispatch.
 */
public class HmacOperations {

    public byte[] computeHmacSha256(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    public byte[] computeHmacSha512(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA512");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA512");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    /**
     * Weak: HmacMD5 is considered insecure.
     */
    public byte[] computeHmacMd5(byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacMD5");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacMD5");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    /**
     * Dynamic algorithm — crypto-finder must track the parameter to resolve the actual algorithm.
     */
    public byte[] computeHmac(String algorithm, byte[] key, byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    /**
     * Commons Codec wrapper — no direct JCE call, crypto-finder must trace through HmacUtils.
     */
    public byte[] computeHmacSha256ViaCommons(byte[] key, byte[] data) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmac(data);
    }

    public String computeHmacSha256HexViaCommons(byte[] key, byte[] data) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmacHex(data);
    }
}
