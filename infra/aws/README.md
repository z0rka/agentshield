# AWS deployment (ECS/Fargate)

**A design document written in Terraform, not a deployment.** Nothing here has been applied and
nothing is meant to be: AgentShield runs on `docker-compose`, which is the topology CI actually
exercises. This directory answers a narrower question - what would the trust boundaries in
`docs/security-architecture.md` look like as infrastructure - and answers it in a language
where the answer can be reviewed line by line.

Read it for the security-group graph in `security-groups.tf` and the role split in `iam.tf`.
Those are the parts with an argument behind them.

## What "never applied" means

No AWS account was involved. `terraform init`, `validate` and `plan` have not run against a
real provider, so every resource is **reviewed but unverified**:

- Argument names and required blocks come from the provider documentation, not from a
  successful plan. Some will be wrong.
- The MSK topic and consumer-group ARNs in `iam.tf` are built by string surgery on the cluster
  ARN. That is the documented shape, and a first `plan` is exactly what would catch it if not.
- The cost table below is an order of magnitude, not a quote.

Kept with the label attached. The reasoning is the deliverable, and an unapplied
configuration that admits it beats no configuration at all.

## What it builds

```
              ┌──────────────────────── VPC, 2 AZs ────────────────────────┐
              │                                                            │
  internet ──►│  public:  ALB, NAT                                         │
              │                                                            │
              │  private: control-plane ──► engine-api                     │
              │                 │  │                                       │
              │                 │  └──► RDS PostgreSQL (encrypted, PITR)   │
              │                 └─────► MSK Serverless ◄── engine-worker   │
              │                                              │             │
              └──────────────────────────────────────────────┼─────────────┘
                                                             ▼
                                                  targets under test
```

| File | Contents |
|---|---|
| `network.tf` | VPC, subnets, NAT, VPC endpoints, flow logs |
| `security-groups.tf` | The access-control policy, as a graph of group references |
| `data-stores.tf` | RDS, MSK Serverless, KMS, empty Secrets Manager entries |
| `iam.tf` | Execution role and one task role per service |
| `ecs.tf` | Cluster, three task definitions, three services |
| `load-balancer.tf` | ALB, target group, listeners |

## Decisions worth arguing with

**The worker has no ingress rules at all.** Not narrow ones - none. It consumes from Kafka and
calls out to the systems under test, both outbound. It is the process that parses adversarial
trajectories and renders them into reports, so nothing in the account being able to open a
connection to it is worth more than any inbound rule could be.

**The worker cannot read the credential encryption key.** It never decrypts a target
configuration; the control plane does that and dispatches the result. Granting the key to the
process that handles attacker-influenced input would undo the reason for encrypting it.

**Secrets are references, never values.** `AGENTSHIELD_CREDENTIAL_KEY` and friends appear in
the `secrets` block of the task definition, resolved at start-up. A plaintext value in
`environment` is readable by anyone holding `ecs:DescribeTaskDefinition`, which is a much larger
group than anyone intends. Terraform creates the secret containers empty and never their
contents, so no secret value is recoverable from state.

**`allowed_ingress_cidrs` defaults to empty.** The first apply produces a deployment nobody can
reach. Opening it is an explicit act. A permissive default in a security tool would be the
exact mistake the tool scans for.

**The database password is managed by RDS.** `manage_master_user_password = true` rotates it
into Secrets Manager. The alternative writes a plaintext credential into Terraform state,
which is a plaintext credential in an S3 bucket no matter how the variable is declared.

**Managed PostgreSQL and managed Kafka.** Self-hosting either is a way to lose findings, and
the findings history is what a regression baseline is compared against.

**No backend block is committed.** A committed backend pointing at someone else's bucket is the
fastest way for a reader to write state into an account they do not own.

## If you did apply it

Recorded for completeness. Nobody has run these.

```bash
cat > backend.hcl <<'EOF'
bucket = "your-terraform-state-bucket"
key    = "agentshield/dev.tfstate"
region = "eu-west-1"
EOF

terraform init -backend-config=backend.hcl
terraform plan -var-file=dev.tfvars
```

Then populate the three secrets before the services will start:

```bash
aws secretsmanager put-secret-value \
  --secret-id agentshield-dev/credential-key \
  --secret-string "$(openssl rand -base64 32)"

aws secretsmanager put-secret-value \
  --secret-id agentshield-dev/internal-token \
  --secret-string "$(openssl rand -hex 32)"

aws secretsmanager put-secret-value \
  --secret-id agentshield-dev/judge-api-key \
  --secret-string "sk-ant-..."
```

The credential key must be exactly 32 bytes base64-encoded; the control plane refuses to start
otherwise, which is the intended behaviour and not a papercut.

## Rough monthly cost

Included because it is part of the design: this topology is expensive enough that running it
for a portfolio would be a bad decision, and that is worth saying out loud next to the code.
Order of magnitude for the `dev` defaults in `eu-west-1`, on-demand, at the time of writing.

| | |
|---|---|
| Fargate, 6 tasks | ~$120 |
| RDS `db.t4g.micro`, single AZ | ~$15 |
| MSK Serverless, idle | ~$100 |
| NAT gateways, 2 | ~$65 + data |
| ALB | ~$20 |
| **Total** | **~$320/month** |

MSK Serverless has a floor charge whether or not anything is published, and two NAT gateways
cost more than the compute they serve. For a demonstration environment, one NAT gateway and a
single-broker MSK provisioned cluster are cheaper; the redundancy here is written for the shape
of a production deployment, not for the cheapest one that boots.

`terraform destroy` will refuse while `database_deletion_protection` is true. That default
is intentional.

## Related

- [../docker-compose.yml](../docker-compose.yml) - the same topology on one machine, and the
  one that is actually tested
- [../../docs/security-architecture.md](../../docs/security-architecture.md) - why the
  boundaries are where they are
