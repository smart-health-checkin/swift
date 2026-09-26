# Agent notes: swift

The Swift package. Swift Package Manager installs it from `vX.Y.Z` tags.
[MAINTAINING.md](https://github.com/smart-health-checkin/smart-health-checkin.github.io/blob/main/MAINTAINING.md) maps every repo, what triggers what, and how to release.

- Test: `scripts/fetch-fixtures.sh && swift test`. The conformance tests read
  the spec's fixtures at the pinned tag (`SPEC_FIXTURES_REF`); CI runs them on
  Linux (`test.yml`).
- **Releasing:** push tag `vX.Y.Z`. The tag is the release. Never re-tag.
- Conformance: `SpecConformanceTests` runs the spec's conformance cases
  (every capability; pinned by `SPEC_CONFORMANCE_REF` in
  `scripts/fetch-conformance.sh`). Credentials built for `wallet-response`
  land in `.build/conformance-wallet/`; CI checks them with the spec's
  reference verifier. `conformance/known-failures.json` lists what fails today
  and must shrink.
