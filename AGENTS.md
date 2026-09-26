# Agent notes: swift

The Swift package. Swift Package Manager installs it from `vX.Y.Z` tags.
[MAINTAINING.md](https://github.com/smart-health-checkin/smart-health-checkin.github.io/blob/main/MAINTAINING.md) maps every repo, what triggers what, and how to release.

- Test: `scripts/fetch-spec.sh && swift test`. The tests read the spec's
  fixtures and conformance cases at the pinned tag (`SPEC_REF`;
  `SPEC_DIR=../spec` uses a local checkout); CI runs them on Linux (`test.yml`). With no local
  toolchain, the same image CI uses works:
  `docker run --rm -v "$PWD":/src -w /src swift:6.1 swift test`.
- **Releasing:** push tag `vX.Y.Z`. The tag is the release. Never re-tag.
- Conformance: `SpecConformanceTests` runs the spec's conformance cases
  (every capability). Credentials built for `wallet-response`
  land in `.build/conformance-wallet/`; CI checks them with the spec's
  reference verifier. `conformance/known-failures.json` is empty; keep it that
  way (a new failure is a bug, not a list entry, unless a spec decision is
  pending).
- Receivers are permissive, producers strict (spec §2 RCV-0..2, decision D16):
  receiver-side problems become `CheckinWarning`s with the conformance codes,
  and only the steps §8 marks **fail** throw.
