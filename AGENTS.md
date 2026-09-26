# Agent notes: swift

The Swift package. Swift Package Manager installs it from `vX.Y.Z` tags.
[MAINTAINING.md](https://github.com/smart-health-checkin/smart-health-checkin.github.io/blob/main/MAINTAINING.md) maps every repo, what triggers what, and how to release.

- Test: `scripts/fetch-fixtures.sh && swift test`. The conformance tests read
  the spec's fixtures at the pinned tag (`SPEC_FIXTURES_REF`); CI runs them on
  Linux (`test.yml`).
- **Releasing:** push tag `vX.Y.Z`. The tag is the release. Never re-tag.
