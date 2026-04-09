package com.mastercard.developer.crypto.thirdparty;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * DEPENDENCY SCANNING TEST — BouncyCastle PKIX wrappers.
 *
 * This class calls BouncyCastle (bcpkix) APIs that internally call JCA.
 * No JCA calls (Cipher.getInstance, KeyFactory.getInstance, etc.) appear
 * in THIS source file — they live inside the bcpkix/bcprov JARs.
 *
 * When the dependency scanner scans the BouncyCastle JARs, it will find
 * JCA calls via semgrep rules. The call graph then traces those findings
 * backwards through this wrapper to user code (CryptoMiddleware → CryptoService).
 *
 * Expected dependency scanning call chains:
 *
 * 1. encryptPrivateKey():
 *    User code → this.encryptPrivateKey()
 *      → JceOpenSSLPKCS8EncryptorBuilder.build()           [bcpkix JAR]
 *        → DefaultJcaJceHelper.createCipher(algorithm)      [bcprov JAR]
 *          → Cipher.getInstance(algorithm)                   [JCA ← semgrep finds this]
 *
 * 2. decryptPrivateKey():
 *    User code → this.decryptPrivateKey()
 *      → JceOpenSSLPKCS8DecryptorProviderBuilder.build()    [bcpkix JAR]
 *        → DefaultJcaJceHelper.createCipher(...)             [bcprov JAR]
 *          → Cipher.getInstance(...)                          [JCA ← semgrep finds this]
 *
 * 3. convertPemKeyPair():
 *    User code → this.convertPemKeyPair()
 *      → JcaPEMKeyConverter.getKeyPair()                    [bcpkix JAR]
 *        → DefaultJcaJceHelper.createKeyFactory(algName)    [bcprov JAR]
 *          → KeyFactory.getInstance(algName)                 [JCA ← semgrep finds this]
 *
 * 4. convertCertificate():
 *    User code → this.convertCertificate()
 *      → JcaX509CertificateConverter.getCertificate()       [bcpkix JAR]
 *        → helper.getCertificateFactory("X.509")             [bcprov JAR]
 *          → CertificateFactory.getInstance("X.509")          [JCA ← semgrep finds this]
 */
public class BouncyCastlePkixCrypto {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Encrypt a private key using PKCS#8 + AES-256-CBC.
     *
     * Inside bcpkix: JceOpenSSLPKCS8EncryptorBuilder.build() calls
     * helper.createCipher("AES/CBC/...") → Cipher.getInstance("AES/CBC/...")
     */
    public byte[] encryptPrivateKey(PrivateKey privateKey, char[] password) throws Exception {
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder =
                new JceOpenSSLPKCS8EncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC);
        encryptorBuilder.setProvider("BC");
        encryptorBuilder.setPassword(password);

        OutputEncryptor encryptor = encryptorBuilder.build();

        JcaPKCS8EncryptedPrivateKeyInfoBuilder pkcs8Builder =
                new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey);

        PKCS8EncryptedPrivateKeyInfo encrypted = pkcs8Builder.build(encryptor);
        return encrypted.getEncoded();
    }

    /**
     * Decrypt a PKCS#8-encrypted private key.
     *
     * Inside bcpkix: JceOpenSSLPKCS8DecryptorProviderBuilder.build() calls
     * helper.createCipher(...) → Cipher.getInstance(...)
     * helper.createSecretKeyFactory(...) → SecretKeyFactory.getInstance(...)
     */
    public PrivateKey decryptPrivateKey(byte[] encryptedPkcs8, char[] password) throws Exception {
        PKCS8EncryptedPrivateKeyInfo encryptedInfo =
                new PKCS8EncryptedPrivateKeyInfo(encryptedPkcs8);

        InputDecryptorProvider decryptorProvider =
                new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider("BC")
                        .build(password);

        PrivateKeyInfo keyInfo = encryptedInfo.decryptPrivateKeyInfo(decryptorProvider);

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        return converter.getPrivateKey(keyInfo);
    }

    /**
     * Convert a PEM-encoded key pair to JCA KeyPair.
     *
     * Inside bcpkix: JcaPEMKeyConverter.getKeyPair() calls
     * helper.createKeyFactory(algName) → KeyFactory.getInstance(algName)
     * where algName is "RSA", "ECDSA", or "DSA" — determined by the key's OID.
     */
    public KeyPair convertPemKeyPair(String pemString) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemString))) {
            Object parsed = parser.readObject();
            if (!(parsed instanceof PEMKeyPair)) {
                throw new IllegalArgumentException("PEM does not contain a key pair");
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getKeyPair((PEMKeyPair) parsed);
        }
    }

    /**
     * Convert a PEM-encoded public key to JCA PublicKey.
     *
     * Inside bcpkix: JcaPEMKeyConverter.getPublicKey() calls
     * helper.createKeyFactory(algName) → KeyFactory.getInstance(algName)
     */
    public PublicKey convertPemPublicKey(String pemString) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemString))) {
            Object parsed = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (parsed instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
                return converter.getPublicKey(
                        (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) parsed);
            }
            throw new IllegalArgumentException("PEM does not contain a public key");
        }
    }

    /**
     * Convert a BouncyCastle X509CertificateHolder to a JCA X509Certificate.
     *
     * Inside bcpkix: JcaX509CertificateConverter.getCertificate() calls
     * helper.getCertificateFactory("X.509") → CertificateFactory.getInstance("X.509")
     */
    public X509Certificate convertCertificate(X509CertificateHolder certHolder) throws Exception {
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    /**
     * Parse a PEM string and convert to a JCA X509Certificate.
     *
     * Combines PEMParser (ASN.1 parsing) + JcaX509CertificateConverter (JCA bridge).
     * Inside bcpkix: CertificateFactory.getInstance("X.509") is called.
     */
    public X509Certificate parsePemCertificate(String pemString) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pemString))) {
            Object parsed = parser.readObject();
            if (!(parsed instanceof X509CertificateHolder)) {
                throw new IllegalArgumentException("PEM does not contain a certificate");
            }
            return convertCertificate((X509CertificateHolder) parsed);
        }
    }

    /**
     * Serialize any crypto object (key, cert) to PEM format.
     *
     * JcaPEMWriter internally uses ASN.1 encoding — no JCA calls,
     * but exercises the PEM serialization path in bcpkix.
     */
    public String toPem(Object cryptoObject) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(cryptoObject);
        }
        return sw.toString();
    }
}
