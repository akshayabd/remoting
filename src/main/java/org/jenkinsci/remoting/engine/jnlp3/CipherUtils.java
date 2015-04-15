package org.jenkinsci.remoting.engine.jnlp3;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

/**
 * Comment here.
 */
public class CipherUtils {

    public static byte[] generate128BitKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public static String keyToString(byte[] key) throws UnsupportedEncodingException {
        return new String(key, "ISO-8859-1");
    }

    public static byte[] keyFromString(String keyString) throws UnsupportedEncodingException {
        return keyString.getBytes("ISO-8859-1");
    }
}
