/*
 * The MIT License
 * 
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi, CloudBees, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.remoting.engine;

import hudson.remoting.Channel;
import hudson.remoting.ChannelBuilder;
import hudson.remoting.EngineListenerSplitter;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Properties;

/**
 * Implementation of the JNLP3-connect protocol.
 *
 * This is an extension of the JNLP1-connect protocol. On successful
 * connection to the master the slave will receive a cookie from the master,
 * which the slave stores.
 *
 * If the slave needs to reconnect it will send the same cookie as part of
 * the new connection request. The master can use the cookie to determine if
 * the incoming request is an initial connection request or a reconnection
 * and take appropriate action.
 *
 * @author Akshay Dayal
 */
public class JnlpProtocol3 extends JnlpProtocol {

    /**
     * This cookie identifies the current connection, allowing us to force the
     * server to drop the client if we initiate a reconnection from our end
     * (even when the server still thinks the connection is alive.)
     */
    private String cookie;
    private Jnlp3Ciphers ciphers;

    JnlpProtocol3(String secretKey, String slaveName, EngineListenerSplitter events) {
        super(secretKey, slaveName, events);
    }

    @Override
    public String getName() {
        return NAME;
    }

    String getCookie() {
        return cookie;
    }

    @Override
    boolean performHandshake(DataOutputStream outputStream,
            BufferedInputStream inputStream) throws IOException {
        try {
            ciphers = Jnlp3Ciphers.createForSlave(slaveName, secretKey, null);
        } catch (Exception e) {
            events.status(NAME + ": Unable to create ciphers", e);
            return false;
        }

        String challenge = generateChallenge();
        events.status(challenge);
        String encryptedChallenge = null;
        try {
            encryptedChallenge = new String(ciphers.getEncryptCipher().doFinal(challenge.getBytes("UTF-8")), "ISO-8859-1");
        } catch (Exception e) {
            events.status(NAME + ": Unable to create encrypted challenge", e);
            return false;
        }

        initiateHandshakeWithChallenge(outputStream, encryptedChallenge, ciphers.getIvParameterSpec());

        Integer challengeResponseLength = Integer.parseInt(EngineUtil.readLine(inputStream));
        events.status("--------------------------->"+challengeResponseLength);
        String encryptedChallengeResponse = EngineUtil.readChars(inputStream, challengeResponseLength);
        events.status("-------------------------->" + encryptedChallengeResponse.length());
        //String f = new String(encryptedChallengeResponse.getBytes("UTF-8"), "ISO-8859-1");
        if (!verifyChallengeResponse(ciphers.getDecryptCipher(), challenge, encryptedChallengeResponse)) {
            return false;
        }
        outputStream.writeUTF(GREETING_SUCCESS);
        cookie = EngineUtil.readLine(inputStream);

        return true;
    }

    private boolean verifyChallengeResponse(Cipher decryptCipher, String challenge, String encryptedChallengeResponse) {
        String decryptedChallengeResponse = null;
        events.status(encryptedChallengeResponse);
        try {
            decryptedChallengeResponse = new String(decryptCipher.doFinal(encryptedChallengeResponse.getBytes("ISO-8859-1")), "UTF-8");
        } catch (Exception e) {
            events.status(NAME + ": Unable to decrypt response from master", e);
            return false;
        }
        events.status(decryptedChallengeResponse);
        if (!decryptedChallengeResponse.startsWith(CHALLENGE_PREFIX)) {
            events.status("Response from master did not start with challenge prefix");
            return false;
        }

        // The master should have reversed the challenge phrase (minus the prefix).
        if (!challenge.substring(CHALLENGE_PREFIX.length()).equals(
                new StringBuilder(decryptedChallengeResponse.substring(CHALLENGE_PREFIX.length())).reverse().toString())) {
            events.status("Master authentication failed");
            return false;
        }

        return true;
    }

    @Override
    Channel buildChannel(Socket socket, ChannelBuilder channelBuilder) throws IOException {
        try {
            ciphers.getEncryptCipher().init(Cipher.ENCRYPT_MODE, ciphers.getSecretKey(), ciphers.getIvParameterSpec());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return channelBuilder.build(
                new CipherInputStream(new BufferedInputStream(socket.getInputStream()), ciphers.getDecryptCipher()),
                new MyOutputStream(new BufferedOutputStream(socket.getOutputStream()), ciphers.getEncryptCipher(), ciphers.getSecretKey(), ciphers.getIvParameterSpec()));
    }

    private void initiateHandshakeWithChallenge(
            DataOutputStream outputStream, String encryptedChallenge, IvParameterSpec spec) throws IOException {
        Properties props = new Properties();
        props.put(SLAVE_NAME_KEY, slaveName);
        props.put(SPEC_KEY, new String(spec.getIV(), "ISO-8859-1"));
        props.put(CHALLENGE_KEY, encryptedChallenge);
        events.status(new String(spec.getIV(), "ISO-8859-1"));
        events.status("" + spec.getIV().length);

        // If there is a cookie send that as well.
        if (cookie != null)
            props.put(COOKIE_KEY, cookie);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        props.store(o, null);

        outputStream.writeUTF(PROTOCOL_PREFIX + NAME);
        outputStream.writeUTF(o.toString("UTF-8"));
    }

    private String generateChallenge() {
        String randomString = new BigInteger(5200, new SecureRandom()).toString(32);
        return CHALLENGE_PREFIX + randomString;
    }

    public static final String NAME = "JNLP3-connect";
    public static final String SPEC_KEY = "Spec";
    public static final String CHALLENGE_KEY = "Challenge";
    public static final String CHALLENGE_RESPONSE_KEY = "Challenge-Response";
    public static final String SLAVE_NAME_KEY = "Node-Name";
    public static final String COOKIE_KEY = "Cookie";
    public static final String CHALLENGE_PREFIX = "JNLP3";
}
