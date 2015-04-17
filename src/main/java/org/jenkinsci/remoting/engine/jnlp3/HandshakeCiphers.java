package org.jenkinsci.remoting.engine.jnlp3;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;

/**
 * Comment here.
 */
public class HandshakeCiphers {

    private final SecretKey secretKey;
    private final IvParameterSpec spec;
    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    HandshakeCiphers(SecretKey secretKey, IvParameterSpec spec, Cipher encryptCipher, Cipher decryptCipher) {
        this.secretKey = secretKey;
        this.spec = spec;
        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;
    }

    public byte[] getSpecKey() {
        return spec.getIV();
    }

    public String encrypt(String raw) throws Exception {
        String encrypted = new String(encryptCipher.doFinal(raw.getBytes("UTF-8")), "ISO-8859-1");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        return encrypted;
    }

    public String decrypt(String encrypted) throws Exception {
        String raw = new String(decryptCipher.doFinal(encrypted.getBytes("ISO-8859-1")), "UTF-8");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        return raw;
    }

    public static HandshakeCiphers create(
            String slaveName, String slaveSecret, @Nullable byte[] specKey) throws Exception {
        if (specKey == null) {
            specKey = CipherUtils.generate128BitKey();
        }

        SecretKey secretKey = generateSecretKey(slaveName, slaveSecret);
        IvParameterSpec spec = new IvParameterSpec(specKey);
        Cipher encryptCipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        Cipher decryptCipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return new HandshakeCiphers(secretKey, spec, encryptCipher, decryptCipher);
    }

    private static SecretKey generateSecretKey(String slaveName, String slaveSecret) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(
                slaveSecret.toCharArray(), slaveName.getBytes("UTF-8"), INTEGRATION_COUNT, KEY_LENGTH);
        SecretKey tmpSecret = factory.generateSecret(spec);
        return new SecretKeySpec(tmpSecret.getEncoded(), SPEC_ALGORITHM);
    }

    static final String CIPHER_TRANSFORMATION = "AES/CTR/PKCS5Padding";
    static final String FACTORY_ALGORITHM = "PBKDF2WithHmacSHA1";
    static final String SPEC_ALGORITHM = "AES";
    static final int INTEGRATION_COUNT = 65536;
    static final int KEY_LENGTH = 128;
}
