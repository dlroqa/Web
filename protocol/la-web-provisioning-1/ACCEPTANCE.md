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

## Frozen revision

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
| Web (`lightagent-control`) | r4 | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` | `f70789ec69c6d747ba5b7c84fe1b3f8db0cba727` | Web L0 (candidate author) | 2026-10-14 | accepted (proposed this candidate) |
| Lightagent | r4 | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` | `f70789ec69c6d747ba5b7c84fe1b3f8db0cba727` | Lightagent L0 review (PR #28) | 2026-10-14 | accepted, with the conditions in Lightagent `docs/integrations/web/ACCEPTANCE.md` |

## History

| Revision | Digest | Candidate commit | Outcome |
|---|---|---|---|
| r1 | `030537b8be8cc003cff31e503343d5082629eab3f3f10c82fb17d7776b24a1d2` | never committed | Rejected by Lightagent (PR #28): RC1–RC4 |
| r2 | `8649b453d55013cc5d35ed81bc052d219c4afd56eec0d031798f680923248b9a` | `d31e544968447c3f7901f004321c20983e879267` (metadata `fbc5c20`) | Rejected by Lightagent (PR #28 `7bd1675`): RC5, RC6 |
| r3 | `bd410d38aab5890eb8ba97cedbd41a3913046f8d1fd90ff4c6d9a171c9d94a8d` | `15f196ca804e7c999a8ace1792443af8ecee3d49` (metadata `227447b`) | Rejected by Lightagent (PR #28 `bcbdcf0`): RC7 |
| r4 | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` | `f70789ec69c6d747ba5b7c84fe1b3f8db0cba727` (metadata `0cf96f3`) | **Accepted by both sides; frozen** (Lightagent PR #28 `d418249`) |

Any change to the specification or a fixture produces a new digest and voids
earlier acceptance rows for that revision.

## Status: FROZEN

`LA-WEB-PROVISIONING/1` revision **r4** is **frozen** as of 2026-10-14. Both
rows above name the same revision (`r4`), compatibility digest
(`454066f8…a43`) and candidate commit (`f70789e`), and both were checked
against the evidence below before this status was written.

Frozen means only that the contract is fixed. **It activates nothing.** No
gateway is mounted, no key is trusted, no harness is registered, no
migration is applied, no secret is configured and nothing is deployed by this
record. Each of those, and every merge, needs its own approval. Any change to
a hashed byte is a new revision (r5) that needs fresh acceptance from both
sides.

### Binding implementation condition (Lightagent L1)

Before any gateway activation, Lightagent L1 MUST implement §10.6 ledger
continuity (C1–C3) through:

1. a **durable, harness-stamped ledger** (`harness_id`, `continuity_id`,
   `retired`), created only by an explicit operator `init`, never lazily;
2. **provisioning continuity** recorded in the identity store
   (`provisioning_continuity = { continuity_id, ledger_generation_seen }`),
   written in the same bind and revoke transactions, with every on-disk
   `.provisioning-operation` marker mapping to a ledger operation (C2); and
3. **identity-generation markers** (`identity_generation_seen` in the
   ledger, checked against the identity store's `generation()`, C3), because
   identity idempotency records are pruned at `MAX_IDEMPOTENCY = 10_000`.

The design is Lightagent `docs/integrations/web/l0-protocol-review.md` §3.
Web treats a harness as unactivatable until Lightagent shows this condition
met, including reproducing `ledger-continuity.json`. Lightagent's further
conditions (step-15 credential mapping, PR #26 public behaviour unchanged,
acceptance ≠ activation) are in its record, copied below.

### Verification evidence (2026-10-14, performed from Web)

| Check | Result |
|---|---|
| `sha256sum MANIFEST.json` at `f70789e` and at this commit's parent `0cf96f3` | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` at both |
| `sha256sum -c MANIFEST.sha256` (specification, 10 fixture files, manifest) | 12/12 `OK` |
| `npm run protocol:fixtures -- check` (deterministic regeneration) | no difference; digest `454066f8…a43` |
| Hashed files changed `f70789e..0cf96f3` | none (only this file) |
| Lightagent pinned mirror `docs/integrations/web/la-web-provisioning-1-r4/` at `d418249` vs Web `f70789e` | 13/13 files byte-identical (specification, 10 fixtures, `MANIFEST.json`, `MANIFEST.sha256`) |
| Lightagent `COMPATIBILITY_DIGEST` (`crates/lightagent-protocol-conformance/tests/fixtures.rs` at `d418249`) | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` |
| Bundle `la-web-provisioning-1-r4.bundle` | SHA-256 `ea4524c4a5197dc765a6f055bad1fabde39537f5ad713314a74ecf7da941e889` (matches sidecar and Lightagent record); `git bundle verify` OK; head `0cf96f3` |
| Lightagent commit `d418249cc00f5f2cd690773d118cb9212e506528` | head of `origin/integration/web-protocol-l0-verify`, draft PR #28 (open, unmerged) |
| GitHub Actions `check` run `38531091889` | completed, **success**, head `d418249` |
| GitHub Actions `jev evaluation` run `38531091940` | completed, **success**, head `d418249` |

## Lightagent acceptance record (verbatim copy)

Copied byte for byte from Lightagent `docs/integrations/web/ACCEPTANCE.md` at
commit `d418249cc00f5f2cd690773d118cb9212e506528` (branch
`integration/web-protocol-l0-verify`, PR #28). The bytes between the markers
have SHA-256
`5ee8ec0756a11b19bcf4051cf3835ec39336cf251a35fb5bf33e6127de79658d`, the same
as the source file. Lightagent's copy is authoritative for its own conditions.

<!-- BEGIN LIGHTAGENT ACCEPTANCE d418249 -->
# LA-WEB-PROVISIONING/1: Lightagent acceptance record

Lightagent's side of the joint acceptance. Web keeps the canonical
`protocol/la-web-provisioning-1/ACCEPTANCE.md`. The protocol is **frozen**
only when Web's row and the row below name the same revision, digest and
candidate commit.

| Field | Value |
|---|---|
| Revision | `la-web-provisioning-1/r4` |
| Compatibility digest (SHA-256 of `MANIFEST.json`) | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` |
| Candidate commit (Web) | `f70789ec69c6d747ba5b7c84fe1b3f8db0cba727` |
| Metadata commit (Web) | `0cf96f3744e986cb506a767b3c350a0c6c9311a7` |
| Delivery | `git bundle` `la-web-provisioning-1-r4.bundle`, SHA-256 `ea4524c4a5197dc765a6f055bad1fabde39537f5ad713314a74ecf7da941e889`, `git bundle verify` OK |
| Pinned mirror | `docs/integrations/web/la-web-provisioning-1-r4/`, and `COMPATIBILITY_DIGEST` in `crates/lightagent-protocol-conformance/tests/fixtures.rs` |
| Evidence | `l0-protocol-review.md`, and draft PR #28 with its GitHub Actions runs |
| Date | 2026-10-14 |
| Verdict | **Accepted** |

## Binding conditions of this acceptance

1. **Ledger continuity (§10.6, P8).** Lightagent's identity idempotency
   records are pruned (`MAX_IDEMPOTENCY = 10_000`). C2 and C3 are therefore
   implemented with the durable generation marker that r4 §10.6 requires in
   that case, as specified in `l0-protocol-review.md` §3, before any
   activation.
2. **Order of steps.** The `keyId` → credential mapping is resolved at step
   15, after the nonce is durably recorded (§10.2).
3. **No change to PR #26's public behaviour.** The fence and deadline live in
   one additive `ProvisioningService` entry point. `provision` and its HTTP
   API stay unchanged.
4. **Acceptance is not activation.** No gateway is mounted, no key is
   trusted, and no harness is registered by this record. Each of those, and
   every merge and deployment, needs separate approval.

## Row for Web's `ACCEPTANCE.md`

| Side | Revision | Compatibility digest | Candidate commit | Reviewer | Date | Verdict |
|---|---|---|---|---|---|---|
| Lightagent | r4 | `454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43` | `f70789ec69c6d747ba5b7c84fe1b3f8db0cba727` | Lightagent L0 review (PR #28) | 2026-10-14 | accepted, with the conditions in Lightagent `docs/integrations/web/ACCEPTANCE.md` |
<!-- END LIGHTAGENT ACCEPTANCE d418249 -->
