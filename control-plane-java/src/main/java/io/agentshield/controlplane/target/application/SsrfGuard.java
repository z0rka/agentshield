package io.agentshield.controlplane.target.application;

import io.agentshield.controlplane.shared.error.InvalidRequestException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Refuses target URLs that point back inside the network AgentShield runs in.
 *
 * <p>This tool exists to send adversarial traffic at whatever URL it is given, which makes an
 * unguarded target registration a server-side request forgery primitive with a scheduler and a
 * retry policy attached. The address that matters most is {@code 169.254.169.254}: on AWS, GCP
 * and Azure it serves instance credentials to anything that asks, and "point the scanner at it
 * and read the findings" is a complete exfiltration path.
 *
 * <p><b>The host is resolved, not merely parsed.</b> Blocking the literal {@code 169.254.169.254}
 * and stopping there accomplishes nothing, because {@code metadata.attacker.test} is a name an
 * attacker controls and can point wherever they like.
 *
 * <p><b>Known limit.</b> Resolution here and connection later are two separate lookups, so a name
 * that answers publicly now and privately in a second still gets through - classic DNS rebinding.
 * Closing it properly means pinning the connection to the address that was validated, which is a
 * change in the HTTP client, not in this class. Documented and not implied: a guard
 * whose gaps are unwritten reads as a guarantee it does not make.
 */
@Component
public class SsrfGuard {

    private static final Logger log = LoggerFactory.getLogger(SsrfGuard.class);

    /**
     * Cloud instance-metadata addresses, refused by name as well as by range.
     *
     * <p>They fall inside link-local and would be caught anyway. Listing them separately buys a
     * refusal message that tells the operator what they just tried to do.
     */
    private static final Set<String> METADATA_ADDRESSES = Set.of(
            "169.254.169.254",   // AWS, Azure, DigitalOcean, Oracle
            "169.254.170.2",     // AWS ECS task metadata
            "100.100.100.200",   // Alibaba Cloud
            "192.0.0.192");      // Oracle Cloud legacy

    private final boolean allowPrivate;

    public SsrfGuard(@Value("${agentshield.security.allow-private-targets:false}") boolean allowPrivate) {
        this.allowPrivate = allowPrivate;
        if (allowPrivate) {
            log.warn("agentshield.security.allow-private-targets is enabled: targets may point at "
                    + "loopback and private addresses. Correct for local development, and a "
                    + "server-side request forgery hole anywhere else.");
        }
    }

    /**
     * Validates a target base URL, throwing {@link InvalidRequestException} when it is unusable.
     *
     * @param baseUrl the URL a caller wants to register as a target
     */
    public void check(String baseUrl) {
        URI uri = parse(baseUrl);
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
            throw new InvalidRequestException("target base_url must be http or https");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new InvalidRequestException("target base_url must include a host");
        }
        for (InetAddress address : resolve(host)) {
            reject(host, address);
        }
    }

    private void reject(String host, InetAddress address) {
        String literal = address.getHostAddress();
        if (METADATA_ADDRESSES.contains(literal)) {
            // Refused even in local development. Nothing legitimate about this tool ever needs
            // to talk to a metadata endpoint, and the credentials behind it are not recoverable
            // by apologising afterwards.
            throw new InvalidRequestException(
                    "target " + host + " resolves to the cloud metadata endpoint " + literal
                            + ", which serves instance credentials and is never a valid target");
        }
        if (allowPrivate) {
            return;
        }
        String reason = classify(address);
        if (reason != null) {
            throw new InvalidRequestException(
                    "target " + host + " resolves to " + literal + " (" + reason + "). Scanning "
                            + "an internal address from the control plane is server-side request "
                            + "forgery. Set agentshield.security.allow-private-targets for local "
                            + "development only.");
        }
    }

    /** The reason an address is off limits, or null when it is a routable public address. */
    private static String classify(InetAddress address) {
        if (address.isLoopbackAddress()) {
            return "loopback";
        }
        if (address.isLinkLocalAddress()) {
            return "link-local";
        }
        if (address.isSiteLocalAddress()) {
            return "private range";
        }
        if (address.isAnyLocalAddress()) {
            return "wildcard";
        }
        if (address.isMulticastAddress()) {
            return "multicast";
        }
        // IPv6 unique-local (fc00::/7). `isSiteLocalAddress` covers the deprecated fec0::/10 and
        // misses this one, which is what current IPv6 deployments actually use.
        byte[] octets = address.getAddress();
        if (octets.length == 16 && (octets[0] & 0xFE) == 0xFC) {
            return "IPv6 unique-local";
        }
        return null;
    }

    private static URI parse(String baseUrl) {
        try {
            return URI.create(baseUrl);
        } catch (IllegalArgumentException exception) {
            throw new InvalidRequestException("target base_url is not a valid URL");
        }
    }

    private static InetAddress[] resolve(String host) {
        try {
            return InetAddress.getAllByName(host);
        } catch (UnknownHostException exception) {
            // Refused, not allowed through. A name that does not resolve cannot be scanned, and
            // treating "cannot check" as "safe" is how guards get bypassed by an outage.
            throw new InvalidRequestException(
                    "target host " + host + " does not resolve, so it cannot be validated");
        }
    }
}
