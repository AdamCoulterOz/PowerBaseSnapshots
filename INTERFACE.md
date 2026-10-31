# Interface

The pipeline polls a caller-configured sentinel and, for a new exact four-part service version, coordinates the pinned private PowerSpec producer's read-only capture and normalization. On qualified success it commits the resulting baseline and creates an immutable annotated `service/<version>` tag. Polling is not a webhook and cannot recover versions skipped between observations; version changes during capture hold the result for retry.

Publication requires complete capture and component-family coverage, an approved field/content policy and attestation bound to the snapshot hash, producer revision, policy, profile and matching before/after versions. Missing or unqualified evidence holds publication. The producer is pinned, but the policy hash and portable families remain unset and the producer does not yet emit the required public attestation; existing capture semantics are not yet qualified.

Retain evidence-backed stable component IDs. Classify installation bookkeeping and environment bindings by field and evidence, never by blindly removing GUIDs. PowerSpec owns semantic model extraction and reference packaging; neither is a stage of this repository's pipeline. Private historical candidates are outside this public history.

Before a new-version publication attempt, fresh discovery and a gated export
inventory report are verified against their catalogue, registries, profile and service
version. Identity/reference coverage must be bound to the normalized snapshot and
discovery and must explicitly establish complete reference evidence; an empty list of
references is not proof. The attestation binds discovery, inventory and identity report
hashes in addition to the existing policy, producer, snapshot and version facts.
Informational `diagnose` does not capture or publish a baseline and exposes only
validated aggregate counts. Unsupported, missing, ambiguous or partial evidence holds.
