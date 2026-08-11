package io.agentshield.controlplane.target.application;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.agentshield.controlplane.shared.error.InvalidRequestException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The guard is the difference between a scanner and an SSRF proxy, so the negative cases are
 * the point. Every address used here is a literal, because a test that depends on DNS resolving
 * an attacker-controlled name is a test that fails in an air-gapped CI runner for a reason that
 * has nothing to do with the code.
 */
class SsrfGuardTest {

    private final SsrfGuard denying = new SsrfGuard(false);
    private final SsrfGuard permissive = new SsrfGuard(true);

    @Nested
    @DisplayName("cloud metadata")
    class Metadata {

        @Test
        void awsMetadataIsRefusedEvenWhenPrivateTargetsAreAllowed() {
            // The one address no configuration may re-enable: it serves instance credentials,
            // and a scan report containing them cannot be un-published.
            assertThatThrownBy(() -> permissive.check("http://169.254.169.254/latest/meta-data/"))
                    .isInstanceOf(InvalidRequestException.class)
                    .hasMessageContaining("metadata")
                    .hasMessageContaining("credentials");
        }

        @Test
        void ecsTaskMetadataIsRefused() {
            assertThatThrownBy(() -> permissive.check("http://169.254.170.2/v2/credentials"))
                    .isInstanceOf(InvalidRequestException.class)
                    .hasMessageContaining("metadata");
        }

        @Test
        void alibabaAndOracleMetadataAreRefused() {
            assertThatThrownBy(() -> permissive.check("http://100.100.100.200/"))
                    .isInstanceOf(InvalidRequestException.class);
            assertThatThrownBy(() -> permissive.check("http://192.0.0.192/"))
                    .isInstanceOf(InvalidRequestException.class);
        }
    }

    @Nested
    @DisplayName("internal ranges")
    class Internal {

        @Test
        void loopbackIsRefusedByDefault() {
            assertThatThrownBy(() -> denying.check("http://127.0.0.1:8090"))
                    .isInstanceOf(InvalidRequestException.class)
                    .hasMessageContaining("loopback");
        }

        @Test
        void privateRangesAreRefusedByDefault() {
            for (String host : new String[] {"10.0.0.5", "172.16.4.9", "192.168.1.20"}) {
                assertThatThrownBy(() -> denying.check("http://" + host))
                        .as("private address %s", host)
                        .isInstanceOf(InvalidRequestException.class)
                        .hasMessageContaining("private range");
            }
        }

        @Test
        void ipv6LoopbackIsRefused() {
            assertThatThrownBy(() -> denying.check("http://[::1]:8080"))
                    .isInstanceOf(InvalidRequestException.class);
        }

        @Test
        void ipv6UniqueLocalIsRefused() {
            // fc00::/7 is what current IPv6 deployments use. `isSiteLocalAddress` does not
            // report it, so an implementation that only asks the JDK misses the whole range.
            assertThatThrownBy(() -> denying.check("http://[fd00::1]"))
                    .isInstanceOf(InvalidRequestException.class)
                    .hasMessageContaining("unique-local");
        }

        @Test
        void wildcardIsRefused() {
            assertThatThrownBy(() -> denying.check("http://0.0.0.0:8090"))
                    .isInstanceOf(InvalidRequestException.class);
        }
    }

    @Nested
    @DisplayName("what must still work")
    class Allowed {

        @Test
        void publicAddressesPass() {
            assertThatCode(() -> denying.check("https://93.184.216.34/api")).doesNotThrowAnyException();
        }

        @Test
        void loopbackPassesWhenLocalDevelopmentEnablesIt() {
            // The demo target runs here. Without this the local profile cannot register a
            // target at all, and a guard that breaks the quickstart gets switched off wholesale.
            assertThatCode(() -> permissive.check("http://127.0.0.1:8090")).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("malformed input")
    class Malformed {

        @Test
        void nonHttpSchemesAreRefused() {
            for (String url : new String[] {
                "file:///etc/passwd", "gopher://x/", "ftp://x/", "jar:file:///x"
            }) {
                assertThatThrownBy(() -> denying.check(url))
                        .as("scheme in %s", url)
                        .isInstanceOf(InvalidRequestException.class);
            }
        }

        @Test
        void aHostThatDoesNotResolveIsRefusedRatherThanAssumedSafe() {
            // "Could not check" must never read as "checked and fine", or a DNS outage
            // becomes a bypass.
            assertThatThrownBy(() ->
                            denying.check("http://no-such-host.invalid"))
                    .isInstanceOf(InvalidRequestException.class)
                    .hasMessageContaining("does not resolve");
        }

        @Test
        void urlWithoutHostIsRefused() {
            assertThatThrownBy(() -> denying.check("http:///path"))
                    .isInstanceOf(InvalidRequestException.class)
                    .hasMessageContaining("host");
        }
    }
}
