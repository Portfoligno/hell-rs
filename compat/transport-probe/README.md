# Authentication transport readiness configuration

This probe checks the protected authentication and GitHub artifact transport path without creating production promotion evidence. Its artifact names, media type, authority domain, reviewer roles, and trust roots are deliberately non-production and are rejected by the production review selectors and verifier.

The committed configuration is intentionally fail-closed. Do not dispatch the probe while either `repository_id` is `0`, either allowed-signers file contains `AAAA`, or the two protected environments are not independently configured.

## Repository configuration

1. Obtain the immutable numeric repository ID with a read-only authenticated query such as `gh api repos/Portfoligno/hell-rs --jq .id`. Independently confirm the value, then place the same positive integer in both `a/transport-probe-policy.toml` and `b/transport-probe-policy.toml`.
2. Create two independent Ed25519 SSH keypairs outside the repository. Do not reuse a production review key or the other probe key.
3. Replace the placeholder in `a/allowed_signers` with the complete public-key line for principal `assurance-transport-probe-a:probe-a`. Replace the placeholder in `b/allowed_signers` with the independent public-key line for principal `assurance-transport-probe-b:probe-b`.
4. Keep all private-key files outside the repository. Store only A's private key as the environment secret `TRANSPORT_PROBE_A_SSH_PRIVATE_KEY` in `compatibility-transport-probe-a`, and only B's private key as `TRANSPORT_PROBE_B_SSH_PRIVATE_KEY` in `compatibility-transport-probe-b`.
5. Protect both environments with independent authorized reviewers, restrict deployment to the `main` branch, and prevent one reviewer or administrator path from satisfying both environments. The reusable signer workflows do not inherit caller secrets.
6. Review the committed trust roots. They require the GitHub OIDC issuer, exact repository, exact `main` ref, distinct signer A/B reusable-workflow identities, and both SSH and Sigstore signatures. Leave the fail-closed `state = "review-required"` fields unchanged; they describe the explicit-review policy, not a disabled switch.

The workflows request OIDC tokens directly from GitHub. There is no OIDC secret to configure. The Sigstore identities are exact, committed signer-workflow references and must match the Fulcio certificates and Rekor entries produced during the run.

## Pre-dispatch checks

Run these checks from a clean checkout of the reviewed `main` revision:

```text
actionlint -no-color -ignore 'unexpected key "queue"' .github/workflows/*.yml
cargo test -p hell-ci --all-features --bin hell-ci policy::tests::transport_probe_workflows_are_nonpublishing_and_production_nonselectable -- --exact
cargo test -p hell-ci --all-features --bin hell-ci policy::tests::promotion_assurance_workflows_pass_strict_policy_scan -- --exact
```

The narrow actionlint exception is for `concurrency.queue: max`, which is separately required exactly by the repository policy scanner. It must not be broadened to hide another diagnostic.

## Dispatch and retained result

Manually dispatch `assurance-transport-readiness.yml` from the exact reviewed `main` revision. Approve signer A and signer B through their separate protected environments and identities.

A successful run must upload the exact subject, packet, both signer envelopes, both signer-local packet and subject selections, raw provider API responses, ZIP archives, workflow-at-head bytes, and one aggregate receipt. Download and preserve the final receipt artifact before its 14-day GitHub retention expires. The aggregate verifier requires both authentications over the same subject and stable provider identity while retaining each independently timed provider response digest.

Success establishes only authentication and artifact-transport readiness for that immutable run, attempt, workflow head, repository ID, and artifact IDs. It does not authorize publication, push `main`, satisfy the production regression review gate, or convert the probe artifacts into production evidence.
