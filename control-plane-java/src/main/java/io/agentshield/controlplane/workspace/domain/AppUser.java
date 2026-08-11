package io.agentshield.controlplane.workspace.domain;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.UUID;

/**
 * A person.
 *
 * <p>Named {@code AppUser} over {@code User} because {@code user} is reserved in
 * PostgreSQL - a table called {@code user} needs quoting in every hand-written query, and
 * someone will eventually forget.
 */
@Entity
@Table(name = "app_user")
public class AppUser extends BaseEntity {

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    /** BCrypt hash. Null for federated identities. */
    @Column(name = "password_hash")
    private String passwordHash;

    @Column(name = "external_identity")
    private String externalIdentity;

    protected AppUser() {
    }

    public AppUser(UUID id, String email, String displayName, String passwordHash) {
        super(id);
        this.email = email;
        this.displayName = displayName;
        this.passwordHash = passwordHash;
    }

    public String getEmail() {
        return email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getExternalIdentity() {
        return externalIdentity;
    }
}
