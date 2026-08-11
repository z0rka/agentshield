package io.agentshield.controlplane.target.application;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Envelope encryption for target credentials at rest.
 *
 * <p>AES-256-GCM: authenticated, so ciphertext cannot be tampered with undetected, and a fresh
 * random 12-byte nonce per encryption. Reusing a nonce with the same key in GCM is
 * catastrophic - it leaks the XOR of the plaintexts and the authentication key - so the nonce
 * is generated per call and prefixed to the ciphertext, never configured anywhere.
 *
 * <p>The stored blob is {@code nonce || ciphertext || tag}. There is no separate IV column
 * because a nonce that lives apart from its ciphertext eventually gets mismatched by a
 * migration.
 *
 * <p>In production the key belongs in a KMS or secrets manager; this class deliberately keeps
 * the key handling in one place so swapping the source is a single change.
 */
@Component
public class CredentialCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_BYTES = 32;

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    public CredentialCipher(
            @Value("${agentshield.credential-key:}") String base64Key, Environment environment) {
        boolean development = environment.matchesProfiles("local", "test", "default");
        if (base64Key == null || base64Key.isBlank()) {
            if (!development) {
                throw new IllegalStateException(
                        "agentshield.credential-key is required outside local/test profiles");
            }
            // Ephemeral key so a developer can boot without ceremony. Restarting the app makes
            // previously stored credentials undecryptable, which is the correct outcome: a
            // throwaway key must never look like a working one.
            byte[] generated = new byte[KEY_BYTES];
            random.nextBytes(generated);
            this.key = new SecretKeySpec(generated, "AES");
            return;
        }

        byte[] decoded = Base64.getDecoder().decode(base64Key.trim());
        if (decoded.length != KEY_BYTES) {
            throw new IllegalStateException(
                    "agentshield.credential-key must decode to exactly 32 bytes, got "
                            + decoded.length);
        }
        this.key = new SecretKeySpec(decoded, "AES");
    }

    public byte[] encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);

            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] envelope = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, envelope, 0, nonce.length);
            System.arraycopy(ciphertext, 0, envelope, nonce.length, ciphertext.length);
            return envelope;
        } catch (Exception exception) {
            // Never include the plaintext or the key in the message.
            throw new IllegalStateException("failed to encrypt target configuration", exception);
        }
    }

    public String decrypt(byte[] envelope) {
        if (envelope == null || envelope.length <= NONCE_BYTES) {
            return null;
        }
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            System.arraycopy(envelope, 0, nonce, 0, NONCE_BYTES);

            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            byte[] plaintext = cipher.doFinal(
                    envelope, NONCE_BYTES, envelope.length - NONCE_BYTES);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception exception) {
            throw new IllegalStateException("failed to decrypt target configuration", exception);
        }
    }
}
