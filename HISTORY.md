# History

## 2026-10-31

- Established a separate public pipeline history for sentinel-based normalized baseline publication, retaining private candidate history separately. PowerSpec remains the producer and semantic extraction owner.
- Publication is gated on full coverage, an approved field/content policy and bound attestation. Current configuration intentionally holds; synthetic test success is not live publication proof.
- Pinned the private producer distribution and verified its dedicated read-only SSH access. Azure OIDC trust and the protected environment branch restriction are configured; Dataverse read authorization and runtime execution remain pending. Ten offline pipeline tests, a targeted origin/policy case and 23 producer CLI tests passed.
- Verified the application user has ten read privileges and no effective writes, and remote offline CI passed. A GitHub live check subsequently authenticated via OIDC and read service version `9.2.26094.166`; full capture and publication remain unverified; no Azure client secret or Azure RBAC role was added.
- Corrected the federated subject to the observed immutable owner/repository-ID form after the initial OIDC failure, without broadening issuer, audience or branch trust. Scheduled publication remains held by unqualified policy.
