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
| Revision | `la-web-provisioning-1/r3` |
| Compatibility digest | recorded in the metadata commit that follows the candidate commit |
| Candidate commit (Web) | recorded in the metadata commit that follows it |
| Web branch | `l0/la-web-provisioning-r3` (local; the Web repository has no remote) |
| Portable delivery | recorded in the metadata commit (`git bundle` path and SHA-256) |

## Acceptance

| Side | Revision | Compatibility digest | Candidate commit | Reviewer | Date | Verdict |
|---|---|---|---|---|---|---|
| Web (`lightagent-control`) | r3 | | | | | candidate, not accepted |
| Lightagent | r3 | | | | | not yet reviewed |

## History

| Revision | Digest | Candidate commit | Outcome |
|---|---|---|---|
| r1 | `030537b8be8cc003cff31e503343d5082629eab3f3f10c82fb17d7776b24a1d2` | never committed | Rejected by Lightagent (PR #28): RC1–RC4 |
| r2 | `8649b453d55013cc5d35ed81bc052d219c4afd56eec0d031798f680923248b9a` | `d31e544968447c3f7901f004321c20983e879267` (metadata `fbc5c20`, branch `l0/la-web-provisioning-r2`) | Rejected by Lightagent (PR #28 `7bd1675`): RC5, RC6 |

Any change to the specification or a fixture produces a new digest and voids
earlier acceptance rows for that revision.
