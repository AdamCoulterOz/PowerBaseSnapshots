# Context

PowerBaseSnapshots is the public publication pipeline and version history for normalized, observed Power Platform baselines. PowerSpec remains the private producer and owns semantic C# extraction. This repository coordinates sentinel polling, capture, normalization and publication; it does not generate PowerSpec models.

A new observed service version is intended to produce a whole qualified baseline and an immutable annotated `service/<version>` tag. A poll can miss intermediate versions. Before/after version mismatch holds publication for retry; matching observations do not prove an atomic capture.

The private producer is pinned at `4d55129c7589ba64b3a6e8655f6175ebdb097a45`; its read-only deploy key and environment secret are configured and strict SSH clone was verified. Azure OIDC trust and the main-branch environment restriction are configured; the Dataverse application user has ten verified read privileges and no effective writes, and a GitHub live check authenticated through OIDC and read service version `9.2.26094.166`. Publication remains blocked: the approved policy hash is null, portable families are empty, and the producer does not emit the required public attestation. Ten offline pipeline tests, a targeted origin/policy case, 23 producer CLI tests and remote offline CI passed; full capture and complete baselines remain unverified. The earlier personal candidate is isolated in private history and is not a public baseline.

The public pipeline branch is separate from the private candidate history. Never push the private branch or use `--all`/`--mirror`. No service-version tag or baseline data has been published. The application identity uses no Azure client secret or Azure RBAC role.

The live check passed after federated trust was corrected to the observed immutable owner/repository-ID subject without broadening issuer, audience or branch restrictions. Scheduled runs hold while the publication policy is unqualified. Public main contains pipeline code only and no service-version tag or baseline data.
