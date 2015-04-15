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
import org.jenkinsci.remoting.engine.jnlp3.ChannelCiphers;
import org.jenkinsci.remoting.engine.jnlp3.CipherUtils;
import org.jenkinsci.remoting.engine.jnlp3.HandshakeCiphers;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
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
    private ChannelCiphers channelCiphers;
    private HandshakeCiphers handshakeCiphers;

    JnlpProtocol3(String slaveName, String slaveSecret, EngineListenerSplitter events) {
        super(slaveName, slaveSecret, events);
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
        //HandshakeCiphers handshakeCiphers = null;
        try {
            handshakeCiphers = HandshakeCiphers.create(slaveName, slaveSecret, null);
        } catch (Exception e) {
            events.status(NAME + ": Failed to create handshake ciphers", e);
            return false;
        }

        String challenge = generateChallenge();
        if (!initiateHandshakeWithChallenge(challenge, outputStream, handshakeCiphers)) {
            return false;
        }

        if (!verifyChallengeResponse(challenge, inputStream, handshakeCiphers)) {
            return false;
        }

        // Master authenticated, send encryption keys to use for Channel.
        try {
            channelCiphers = ChannelCiphers.create();
        } catch (Exception e) {
            events.status(NAME + ": Failed to create channel ciphers", e);
            return false;
        }
        outputStream.writeUTF(GREETING_SUCCESS);
        try {
            outputStream.writeUTF(handshakeCiphers.encrypt(CipherUtils.keyToString(channelCiphers.getAesKey())));
            outputStream.writeUTF(handshakeCiphers.encrypt(CipherUtils.keyToString(channelCiphers.getSpecKey())));
        } catch (Exception e) {
            events.status(NAME + ": Failed to encrypt channel ciphers", e);
            return false;
        }

        cookie = EngineUtil.readLine(inputStream);
        return true;
    }

    @Override
    Channel buildChannel(Socket socket, ChannelBuilder channelBuilder) throws IOException {
        return channelBuilder.build(
                //new CipherInputStream(socket.getInputStream(), channelCiphers.getDecryptCipher()),
                //new CipherOutputStream(socket.getOutputStream(), channelCiphers.getEncryptCipher())
                new CipherInputStream(socket.getInputStream(), handshakeCiphers.decryptCipher),
                new CipherOutputStream(socket.getOutputStream(), handshakeCiphers.encryptCipher)
        );
    }

    private boolean verifyChallengeResponse(
            String challenge, BufferedInputStream inputStream, HandshakeCiphers handshakeCiphers) throws IOException {
        Integer challengeResponseLength = Integer.parseInt(EngineUtil.readLine(inputStream));
        String encryptedChallengeResponse = EngineUtil.readChars(inputStream, challengeResponseLength);
        String challengeResponse = null;
        try {
            challengeResponse = handshakeCiphers.decrypt(encryptedChallengeResponse);
        } catch (Exception e) {
            events.status(NAME + ": Failed to decrypt response from master", e);
            return false;
        }

        if (!challengeResponse.startsWith(CHALLENGE_PREFIX)) {
            events.status("Response from master did not start with challenge prefix");
            return false;
        }

        // The master should have reversed the challenge phrase (minus the prefix).
        if (!challenge.substring(CHALLENGE_PREFIX.length()).equals(
                new StringBuilder(challengeResponse.substring(CHALLENGE_PREFIX.length())).reverse().toString())) {
            events.status("Master authentication failed");
            return false;
        }

        return true;
    }

    private boolean initiateHandshakeWithChallenge(
            String challenge, DataOutputStream outputStream, HandshakeCiphers handshakeCiphers) throws IOException {
        String encryptedChallenge = null;
        try {
            encryptedChallenge = handshakeCiphers.encrypt(challenge);
        } catch (Exception e) {
            events.status(NAME + ": Failed to create encrypted challenge", e);
            return false;
        }

        Properties props = new Properties();
        props.put(SLAVE_NAME_KEY, slaveName);
        props.put(HANDSHAKE_SPEC_KEY, CipherUtils.keyToString(handshakeCiphers.getSpecKey()));
        props.put(CHALLENGE_KEY, encryptedChallenge);

        // If there is a cookie send that as well.
        if (cookie != null) {
            props.put(COOKIE_KEY, cookie);
        }
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        props.store(o, null);

        outputStream.writeUTF(PROTOCOL_PREFIX + NAME);
        outputStream.writeUTF(o.toString("UTF-8"));
        return true;
    }

    private String generateChallenge() {
        String randomString = new BigInteger(5200, new SecureRandom()).toString(32);
        return CHALLENGE_PREFIX + randomString;
    }

    public static final String CHALLENGE_KEY = "Challenge";
    public static final String CHALLENGE_PREFIX = "JNLP3";
    public static final String COOKIE_KEY = "Cookie";
    public static final String HANDSHAKE_SPEC_KEY = "Handshake-Spec";
    public static final String NAME = "JNLP3-connect";
    public static final String SLAVE_NAME_KEY = "Node-Name";
}
