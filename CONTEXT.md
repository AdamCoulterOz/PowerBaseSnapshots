# Context

PowerBaseSnapshots is the public publication pipeline and version history for normalized, observed Power Platform baselines. PowerSpec remains the private producer and owns semantic C# extraction. This repository coordinates sentinel polling, capture, normalization and publication; it does not generate PowerSpec models.

A new observed service version is intended to produce a whole qualified baseline and an immutable annotated `service/<version>` tag. A poll can miss intermediate versions. Before/after version mismatch holds publication for retry; matching observations do not prove an atomic capture.

The private producer is pinned at `13ad120b7a6bafa1dff0096f56a12b67064be695`; its read-only deploy key and environment secret are configured and strict SSH clone was verified. Azure OIDC trust and the main-branch environment restriction are configured; the Dataverse application user has 14 verified Global read privileges and no effective writes, and a GitHub live check authenticated through OIDC and read service version `9.2.26094.166`. Publication remains blocked: the approved policy hash is null, portable families are empty, and the producer does not emit the required public attestation. Remote CI run `41209729133` passed 18 offline pipeline tests, and 55 tests passed in the reviewed producer distribution; full capture and complete baselines remain unverified. The earlier personal candidate is isolated in private history and is not a public baseline.

The public pipeline branch is separate from the private candidate history. Never push the private branch or use `--all`/`--mirror`. No service-version tag or baseline data has been published. The application identity uses no Azure client secret or Azure RBAC role.

The live check passed after federated trust was corrected to the observed immutable owner/repository-ID subject without broadening issuer, audience or branch restrictions. Scheduled runs hold while the publication policy is unqualified. Public main contains pipeline code only and no service-version tag or baseline data.

The controller requires fresh discovery and export/identity qualification before a
new-version capture and offers a manual diagnostic mode. It does not perform C# extraction
and keeps raw configuration private. The producer does not establish complete snapshot
reference evidence, so the reference-closure gate remains closed even if other flags are
asserted. The dedicated role gained four observed-needed reads (`prvReadEntity`,
`prvReadOptionSet`, `prvReadAttribute`, `prvReadRelationship`); no EntityKey privilege
was added. Eight read-only impersonated metadata probes returned HTTP 200.
[Live diagnostic run 41210320964](https://github.com/AdamCoulterOz/PowerBaseSnapshots/actions/runs/41210320964) completed successfully: OIDC,
producer clone/checkout, discovery, inventory and identity preflight ran against service
version `9.2.26094.166`. Among 126 in-use types, nine were unresolved and none ambiguous;
identity rules were 115 unregistered and 11 partial, while export included 11 partial
types. Reference completeness was not evaluated. The run did not attempt publication.
