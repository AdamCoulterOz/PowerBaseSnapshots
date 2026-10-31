# History

## 2026-10-31

- Established a separate public pipeline history for sentinel-based normalized baseline publication, retaining private candidate history separately. PowerSpec remains the producer and semantic extraction owner.
- Publication is gated on full coverage, an approved field/content policy and bound attestation. Current configuration intentionally holds; synthetic test success is not live publication proof.
- Pinned the private producer distribution and verified its dedicated read-only SSH access. Azure OIDC trust and the protected environment branch restriction are configured; Dataverse read authorization and runtime execution remain pending. Ten offline pipeline tests, a targeted origin/policy case and 23 producer CLI tests passed.
