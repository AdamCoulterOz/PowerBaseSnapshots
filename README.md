# PowerBaseSnapshots

This public repository is intended to capture and normalize a whole observed Power Platform baseline whenever a sentinel reports a new service version. Git commits preserve baseline versions and annotated `service/<version>` tags identify accepted exact versions. The pipeline contains capture coordination only; PowerSpec owns the producer and semantic extraction. There is no PowerSpec C# extraction or package-generation stage here.

Publication currently **holds closed**. The producer is pinned, but the approved policy hash is null and portable families are empty. The producer does not yet issue the required public attestation. The current PowerSpec capture semantics are not yet qualified for complete public baseline publication. A successful release requires complete coverage, an approved field/content policy and a matching attestation bound to the producer, snapshot, policy and observed version. Unknown facts must not be silently discarded. The previous personal candidate and its history remain isolated in the private repository history and are not part of this public history.

The scheduled workflow polls hourly at minute 17 rather than receiving an instant change notification; manual dispatch supports `check` (default) and `run` modes. It observes the sentinel's current version; intermediate versions missed between polls cannot be reconstructed from the later environment. A version change during capture holds publication for a later retry. Successful publication requires before/after capture consistency; this does not make capture atomic.

## Operational setup

Azure workload identity federation and the protected environment main-branch restriction have been configured. The Dataverse application user has ten verified read privileges and no effective write privileges; a GitHub live check authenticated through OIDC and read service version `9.2.26094.166`. Full capture and publication have not been established.

The private PowerSpec producer branch is pinned at `4d55129c7589ba64b3a6e8655f6175ebdb097a45`. Its dedicated read-only deploy key and `PRODUCER_SSH_KEY` environment secret are configured; a strict-host-key clone verified that revision. Set the approved policy hash and portable families only after qualification. Do not put credentials or sentinel details in repository files. The checked-in configuration intentionally cannot authorize full publication today.

Stable component IDs are preserved when supported by evidence. Installation bookkeeping and environment bindings are classified by field and evidence, not by stripping GUID-shaped values. Ten offline pipeline tests and a targeted origin/policy case passed; 23 producer CLI tests also passed. The remote offline CI run passed. These tests do not prove complete capture, portability or publication.

This public branch is isolated from the private candidate history. Do not push the private candidate branch or use `--all` or `--mirror`. No service-version tag or baseline data has been published. The application identity uses no Azure client secret or Azure RBAC role.

The live check passed after the federated trust was corrected to the observed immutable owner/repository-ID subject; issuer, audience and branch restrictions were not broadened. Scheduled runs hold while publication policy remains unqualified. The public main branch contains pipeline code only; no service-version tag or baseline data has been published.
