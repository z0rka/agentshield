package io.agentshield.controlplane.target.application;

import io.agentshield.controlplane.target.application.CredentialCipher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/**
 * Credential encryption.
 *
 * <p>The nonce-reuse test is the important one. AES-GCM fails catastrophically if the same
 * nonce is used twice with one key - it leaks the XOR of the plaintexts and, worse, the
 * authentication key - and the bug is completely invisible from the outside: the ciphertext
 * still decrypts, the tests still pass, and every stored credential is compromised.
 */
class CredentialCipherTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private CredentialCipher cipher() {
        return new CredentialCipher(KEY, new MockEnvironment().withProperty("x", "y"));
    }

    @Test
    @DisplayName("round-trips a configuration document")
    void roundTrips() {
        var cipher = cipher();
        String plaintext = "{\"base_url\":\"https://agent.test\",\"api_key\":\"secret-value\"}";

        String recovered = cipher.decrypt(cipher.encrypt(plaintext));

        assertThat(recovered).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("uses a fresh nonce for every encryption")
    void neverReusesANonce() {
        var cipher = cipher();
        String plaintext = "the same input every time";

        byte[] first = cipher.encrypt(plaintext);
        byte[] second = cipher.encrypt(plaintext);

        // Identical plaintext must never produce identical ciphertext.
        assertThat(first).isNotEqualTo(second);

        byte[] firstNonce = java.util.Arrays.copyOf(first, 12);
        byte[] secondNonce = java.util.Arrays.copyOf(second, 12);
        assertThat(firstNonce).isNotEqualTo(secondNonce);

        assertThat(cipher.decrypt(first)).isEqualTo(plaintext);
        assertThat(cipher.decrypt(second)).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("rejects tampered ciphertext instead of returning garbage")
    void detectsTampering() {
        var cipher = cipher();
        byte[] envelope = cipher.encrypt("{\"api_key\":\"original\"}");
        envelope[envelope.length - 1] ^= 0x01;

        assertThatThrownBy(() -> cipher.decrypt(envelope))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("the plaintext never appears in the stored blob")
    void ciphertextDoesNotContainPlaintext() {
        var cipher = cipher();
        String secret = "AGENTSHIELD_SECRET_7F93A";

        byte[] envelope = cipher.encrypt("{\"api_key\":\"" + secret + "\"}");

        assertThat(new String(envelope, StandardCharsets.ISO_8859_1)).doesNotContain(secret);
    }

    @Test
    @DisplayName("refuses a key of the wrong length")
    void rejectsShortKey() {
        String tooShort = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatThrownBy(() -> new CredentialCipher(tooShort, new MockEnvironment()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    @DisplayName("refuses to start without a key outside development profiles")
    void requiresKeyInProduction() {
        var production = new MockEnvironment();
        production.setActiveProfiles("production");

        assertThatThrownBy(() -> new CredentialCipher("", production))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("credential-key is required");
    }
}
