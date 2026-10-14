# LA-WEB-PROVISIONING/1 acceptance record

This file is review metadata. It is **not** in the manifest, so editing it
never changes the digest it records (PROVISIONING_PROTOCOL §15).

- **Hashed contents:** `docs/PROVISIONING_PROTOCOL.md` and every fixture file
  listed in `MANIFEST.json`.
- **Compatibility digest:** the SHA-256 of `MANIFEST.json` exactly as
  committed. Check it with `sha256sum protocol/la-web-provisioning-1/MANIFEST.json`,
  then `sha256sum -c protocol/la-web-provisioning-1/MANIFEST.sha256` from the
  repository root. `npm run protocol:fixtures -- check` also regenerates every
  file and prints the digest.
- **Candidate commit:** the Web commit that introduced those bytes. A later
  metadata-only commit records it here.

The protocol is **frozen** only when the Web row and the Lightagent row name
the same revision, digest and candidate commit. Until then it is a
**candidate**, and neither side may activate signed provisioning.

## Current candidate

| Field | Value |
|---|---|
| Revision | `la-web-provisioning-1/r4` |
| Compatibility digest | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` |
| Candidate commit (Web) | `f70789ec69c6d747ba5b7c84fe1b3f8db0cba727` (parent `227447b`, the r3 metadata commit) |
| Fixture digest | `bfd171db27c03321227bec1a0e40325bad295b2a228cf02294b3a1e3a87d6e4b` |
| Specification SHA-256 | `5f65a623aa467ec940d2942583a821b6dd23bf7b9221ccaa8e3e72fc4687b36a` |
| Web branch | `l0/la-web-provisioning-r4` (local; the Web repository has no remote) |
| Portable delivery | `git bundle` of branch `l0/la-web-provisioning-r4` with full ancestry: `/home/agent/Repositories/Web-L0-review/la-web-provisioning-1-r4.bundle`. Its SHA-256 is in the sidecar `.sha256` next to it, not here (the bundle contains this file) |

## Acceptance

| Side | Revision | Compatibility digest | Candidate commit | Reviewer | Date | Verdict |
|---|---|---|---|---|---|---|
| Web (`lightagent-control`) | r4 | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` | `f70789ec69c6d747ba5b7c84fe1b3f8db0cba727` | | 2026-10-14 | proposed candidate; awaiting Lightagent |
| Lightagent | r4 | | | | | not yet reviewed |

## History

| Revision | Digest | Candidate commit | Outcome |
|---|---|---|---|
| r1 | `030537b8be8cc003cff31e503343d5082629eab3f3f10c82fb17d7776b24a1d2` | never committed | Rejected by Lightagent (PR #28): RC1–RC4 |
| r2 | `8649b453d55013cc5d35ed81bc052d219c4afd56eec0d031798f680923248b9a` | `d31e544968447c3f7901f004321c20983e879267` (metadata `fbc5c20`) | Rejected by Lightagent (PR #28 `7bd1675`): RC5, RC6 |
| r3 | `bd410d38aab5890eb8ba97cedbd41a3913046f8d1fd90ff4c6d9a171c9d94a8d` | `15f196ca804e7c999a8ace1792443af8ecee3d49` (metadata `227447b`) | Rejected by Lightagent (PR #28 `bcbdcf0`): RC7 |

Any change to the specification or a fixture produces a new digest and voids
earlier acceptance rows for that revision.
