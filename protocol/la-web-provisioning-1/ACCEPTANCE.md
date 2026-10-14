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
| Revision | `la-web-provisioning-1/r2` |
| Compatibility digest | `8649b453d55013cc5d35ed81bc052d219c4afd56eec0d031798f680923248b9a` |
| Candidate commit (Web) | `d31e544968447c3f7901f004321c20983e879267` (parent `775c7c7`) |
| Fixture digest | `49c28a8b49d8c4b0d01ff7cd89df48fe2536ca68faee9dbbddd9df842ac51f55` |
| Specification SHA-256 | `9c92514d1a5f53c450887c48ccdeb594cd253485253016e14850a3e0b8e1efef` |
| Web branch | `l0/la-web-provisioning-r2` (local; the Web repository has no remote) |

## Acceptance

| Side | Revision | Compatibility digest | Candidate commit | Reviewer | Date | Verdict |
|---|---|---|---|---|---|---|
| Web (`lightagent-control`) | r2 | `8649b453d55013cc5d35ed81bc052d219c4afd56eec0d031798f680923248b9a` | `d31e544968447c3f7901f004321c20983e879267` | | 2026-10-13 | proposed candidate; awaiting Lightagent |
| Lightagent | r2 | | | | | not yet reviewed |

## History

| Revision | Digest | Outcome |
|---|---|---|
| r1 | `030537b8be8cc003cff31e503343d5082629eab3f3f10c82fb17d7776b24a1d2` | Rejected by Lightagent (PR #28, `l0-protocol-review.md`): RC1–RC4. It was never committed in Web |

Any change to the specification or a fixture produces a new digest and voids
earlier acceptance rows for that revision.
