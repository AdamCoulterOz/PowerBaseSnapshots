# History

## 2026-10-31

- Added four individually observed-needed metadata reads to the dedicated sentinel role: `prvReadEntity`, `prvReadOptionSet`, `prvReadAttribute` and `prvReadRelationship`. Its final effective privileges are 14 Global reads and no writes; no EntityKey privilege was granted. Eight impersonated read-only metadata probes returned HTTP 200. The subsequent [live diagnostic run 41210320964](https://github.com/AdamCoulterOz/PowerBaseSnapshots/actions/runs/41210320964) succeeded on version `9.2.26094.166`: 126 in-use types, nine unresolved, zero ambiguous; identity rules were 115 unregistered and 11 partial, and export included 11 partial types. Reference completeness was not evaluated and publication was not attempted. Remote CI `41209729133` passed 18 offline pipeline tests.

- Prepared local discovery, export-inventory and snapshot identity/reference qualification gates with a diagnostic-only mode. The new producer distribution passed 55 offline tests and the initial controller pass had 15 local offline tests; later remote CI passed 18 tests. A subsequent diagnostic verified the live discovery and preflight stages, not full capture or publication. An empty reference list is not evidence of closure, and the existing policy and attestation gates remain in force.

- Established a separate public pipeline history for sentinel-based normalized baseline publication, retaining private candidate history separately. PowerSpec remains the producer and semantic extraction owner.
- Publication is gated on full coverage, an approved field/content policy and bound attestation. Current configuration intentionally holds; synthetic test success is not live publication proof.
- Pinned the private producer distribution and verified its dedicated read-only SSH access. At that checkpoint Azure OIDC trust and the protected environment branch restriction were configured; Dataverse read authorization and runtime execution were pending. Ten offline pipeline tests, a targeted origin/policy case and 23 producer CLI tests passed.
- Initially verified the application user had ten read privileges and no effective writes, and remote offline CI passed. A GitHub live check subsequently authenticated via OIDC and read service version `9.2.26094.166`; full capture and publication remain unverified; no Azure client secret or Azure RBAC role was added.
- Corrected the federated subject to the observed immutable owner/repository-ID form after the initial OIDC failure, without broadening issuer, audience or branch trust. Scheduled publication remains held by unqualified policy.

## 2026-11-01

- Switched the sentinel secret to the user-selected dedicated Developer reference environment
  and selected profile `developerreference`. Provisioned the existing application registration
  with a dedicated role containing exactly 14 verified Global reads and no effective writes;
  an impersonated version read returned `9.2.26094.165`. No workflow was run against this target
  as part of the switch; publication qualification remains open.
