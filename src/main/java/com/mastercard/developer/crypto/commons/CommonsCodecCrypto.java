package com.mastercard.developer.crypto.commons;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

/**
 * Crypto operations via Apache Commons Codec.
 * No direct JCE calls — crypto-finder must trace through the library.
 */
public class CommonsCodecCrypto {

    public String sha256Hex(byte[] data) {
        return DigestUtils.sha256Hex(data);
    }

    public String sha512Hex(byte[] data) {
        return DigestUtils.sha512Hex(data);
    }

    /**
     * Weak: MD5 is broken for collision resistance.
     */
    public String md5Hex(byte[] data) {
        return DigestUtils.md5Hex(data);
    }

    /**
     * Weak: SHA-1 is deprecated for most uses.
     */
    public String sha1Hex(byte[] data) {
        return DigestUtils.sha1Hex(data);
    }

    public byte[] sha256(byte[] data) {
        return DigestUtils.sha256(data);
    }

    public byte[] hmacSha256(byte[] key, byte[] data) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmac(data);
    }

    public String hmacSha256Hex(byte[] key, byte[] data) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key).hmacHex(data);
    }

    public byte[] hmacSha512(byte[] key, byte[] data) {
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_512, key).hmac(data);
    }
}
