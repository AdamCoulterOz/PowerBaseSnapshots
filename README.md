# PowerBaseSnapshots

This repository coordinates read-only Power Platform sentinel polling and publishes qualified, normalized raw baselines. PowerSpec owns acquisition, projection and semantic extraction. See [CONTEXT.md](CONTEXT.md) for current status and [INTERFACE.md](INTERFACE.md) for the publication contract.

The scheduled job polls weekly on Saturday at 15:17 UTC (Sunday at 02:17 Sydney daylight time or 01:17 standard time). `check` only observes the version; `auth-check` verifies the configured OIDC identity and bounded read capabilities; `diagnose` runs informational discovery; `run` requires an approved producer policy and finalizer attestation before publication. Matching capture brackets are not an atomicity guarantee. Qualified publications include a deterministic file-hash diff against the previous public baseline. No baseline is qualified or published yet.

Run offline checks with `python3 -m unittest discover -s tests -q`.
