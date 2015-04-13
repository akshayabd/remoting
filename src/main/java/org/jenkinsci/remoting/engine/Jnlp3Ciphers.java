package org.jenkinsci.remoting.engine;

import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

/**
 * Comment here.
 */
public class Jnlp3Ciphers {

    private final Cipher encryptCipher;
    private final Cipher decryptCipher;
    private final IvParameterSpec ivParameterSpec;
    private final SecretKey secretKey;

    Jnlp3Ciphers(Cipher encryptCipher, Cipher decryptCipher, SecretKey secretKey, IvParameterSpec spec) {
        this.encryptCipher = encryptCipher;
        this.decryptCipher = decryptCipher;
        this.secretKey = secretKey;
        this.ivParameterSpec = spec;
    }

    public Cipher getEncryptCipher() {
        return encryptCipher;
    }

    public Cipher getDecryptCipher() {
        return decryptCipher;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public IvParameterSpec getIvParameterSpec() {
        return ivParameterSpec;
    }

    public static Jnlp3Ciphers createForSlave(String slaveName, String slaveSecret, @Nullable IvParameterSpec spec)
            throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
        SecretKey cipherSecretKey = getCipherSecretKey(slaveName, slaveSecret);
        Cipher encryptCipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        if (spec == null) {
            encryptCipher.init(Cipher.ENCRYPT_MODE, cipherSecretKey);
            spec = encryptCipher.getParameters().getParameterSpec(IvParameterSpec.class);
        } else {
            encryptCipher.init(Cipher.ENCRYPT_MODE, cipherSecretKey, spec);
        }

        Cipher decryptCipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        decryptCipher.init(Cipher.DECRYPT_MODE, cipherSecretKey, spec);

        return new Jnlp3Ciphers(encryptCipher, decryptCipher, cipherSecretKey, spec);
    }

    private static SecretKey getCipherSecretKey(String slaveName, String slaveSecret)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(FACTORY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(
                slaveSecret.toCharArray(), slaveName.getBytes("UTF-8"), INTERATION_COUNT, KEY_LENGTH);
        SecretKey tmpSecret = factory.generateSecret(spec);
        return new SecretKeySpec(tmpSecret.getEncoded(), SPEC_ALGORITHM);
    }

    static final String SPEC_ALGORITHM = "AES";
    static final String FACTORY_ALGORITHM = "PBKDF2WithHmacSHA1";
    static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    //static final String CIPHER_TRANSFORMATION = "AES/ECB/NoPadding";
    //static final String CIPHER_TRANSFORMATION = "AES/CBC/NoPadding";
    static final int INTERATION_COUNT = 65536;
    static final int KEY_LENGTH = 128;
}
