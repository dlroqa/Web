# LA-WEB-PROVISIONING/1 r4: implementation readiness

The contract is **frozen** at r4, compatibility digest
`454066f8fb75e886119c401e4a45ec15ebf2b83115165b2e1f85180abfd29a43`
(candidate commit `f70789e`). See
[`protocol/la-web-provisioning-1/ACCEPTANCE.md`](../protocol/la-web-provisioning-1/ACCEPTANCE.md).

This file is planning metadata. It is outside the manifest, and nothing in it
has started. **Freezing activates nothing.** Every item below that touches
real keys, real data, a deployment, a merge or gateway activation needs its
own explicit approval when it is reached.

Both repositories build against the same frozen bytes and meet only at the
wire contract. Neither repository's CI, secrets, deployment or approvals
depend on the other's.

## Shared gates (both repositories)

- [ ] Each repository pins `454066f8…a43` and fails its CI if the pinned
      fixtures or the manifest differ by one byte.
- [ ] No change to `docs/PROVISIONING_PROTOCOL.md` or any manifested fixture.
      A needed change is r5 and reopens acceptance on both sides.
- [ ] Only the TEST-ONLY keys of `keys.json` are used in tests. No real key
      appears in either repository, fixture, log or CI output.
- [ ] Cross-repository end-to-end testing waits for a separately approved
      staging environment. Until then each side proves conformance against
      the fixtures alone.
- [ ] Activation of any harness requires, in order: Lightagent's binding
      L1 continuity condition shown met; a per-harness registration review
      (§12.5 reachability, `harnessId`, `keyId`); and a separate approval.

## Lightagent L1 (Rust; GitHub Actions)

Owner: Lightagent. Baseline: PR #26 (service), #27 (audit), #28 (L0
conformance crate). Design reference: Lightagent
`docs/integrations/web/l0-protocol-review.md` §3 and §6, and protocol §16.2.

### Binding condition (before any gateway activation)

- [ ] Ledger fields `harness_id`, `continuity_id` (128 random bits),
      `retired`, `identity_generation_seen`, under the existing ledger lock.
- [ ] Explicit operator `init`; the ledger is never created lazily. `init`
      refuses when any continuity trace exists (ledger continuity, a profile
      marker, or identity `provisioning_continuity`).
- [ ] Operator `retire` marks the ledger retired.
- [ ] Identity document field `provisioning_continuity = { continuity_id,
      ledger_generation_seen }` (serde default), written in the same bind and
      revoke transactions that return `Outcome::Applied { generation }`.
- [ ] C1–C3 run at start, at activation and after every restore; C1 also
      per command under the lock. While failing, the gateway answers
      `LEDGER_CONTINUITY_FAILED` before step 1 and alters nothing.
- [ ] Reproduces all 13 cases of `ledger-continuity.json`, and on real
      stores: pruning beyond 10,000 identity records, a fresh ledger beside
      a retained identity store, and older-restore cases in both directions.

### Remaining L1–L3 items

- [ ] Fail-closed `control_webhooks` configuration, off by default;
      behaviour identical to today when off.
- [ ] Separate, feature-gated, loopback-only router; never merged into
      `router()` without opt-in.
- [ ] Strict parser, value profile, NFC (`icu_normalizer`, no new crate),
      JCS subset and canonical byte comparison, reused from PR #28.
- [ ] Ed25519 through `ring` with an explicit `S < L` check.
- [ ] Durable nonce store (P7), atomic across processes, purged only under
      the ledger lock after raising the fence.
- [ ] `keyId` → credential mapping resolved at step 15, after the nonce is
      durable.
- [ ] One additive `ProvisioningService` entry point (fence and deadline,
      P1, P6) inside `exclusive()`. `provision` and its HTTP API unchanged.
- [ ] L3 tests: lock-wait race past the deadline records nothing; the same
      with a backward clock step and a raised fence; a duplicate of a refused
      create across a restart answers `REPLAY_DETECTED`; a restore never
      lowers the fence.

### Security boundary

- Lightagent holds only Web's **public** verification keys, as a trusted-key
  list in operator configuration. It never holds a Web signing seed.
- Its own credentials (provisioner credential, identity store) never leave
  the harness and are never sent to Web.
- The gateway listens on loopback; any ingress (direct HTTPS or a Cloudflare
  Tunnel per §12.5) is a per-harness deployment decision, approved
  separately.

### Deployment boundary

- No harness registration, trusted key, gateway mount or ingress is created
  by L1 work. The feature stays compiled out or switched off in every build
  until activation is approved.

### CI boundary (GitHub Actions)

- [ ] The existing offline conformance job (`check`) keeps running every
      vector and `sha256sum -c` of the pinned mirror.
- [ ] L1–L3 tests run on all three platforms in GitHub Actions; `jev
      evaluation` stays a required check.
- [ ] A later cross-repository job is reported as **skipped**, not passed,
      when its staging environment is absent.
- [ ] No Web secret, Cloudflare credential or Web deployment step is
      configured in Lightagent's Actions.

## Web W1 (Cloudflare Workers, D1; Wrangler)

Owner: Web (`lightagent-control`). Design reference: protocol §13 and §16.1.

### Order of work

- [ ] **Migration 0003 or later** (never edit 0001 or 0002): §13.10
      transmission journal with triggers and delivery lease; the job's fixed
      canonical payload; job columns `operation_id`, `principal_id`,
      `observed_state`, `observed_at`, `needs_attention`, `next_attempt_at`;
      `attempt_count` decoupled from reconciliation; the suspension path;
      harness retirement records. Written and tested locally only.
- [ ] Restrict `PROVISIONING_OPERATIONS` and `HarnessCapabilitiesSchema` to
      the v1 set (`profile.create`, `profile.status`, `profile.revoke`).
- [ ] Display-name check (§8.1) at profile creation and rename, or at least
      before signing.
- [ ] Production codec under `src/worker/provisioning/`, ported from the
      reference and tested inside workerd against every fixture, including
      `responses.json` and `create-resolution.json`. Fixtures stay
      unreachable from `src/` (existing static test).
- [ ] Transport through `fetchWithTimeout` (10 s, `redirect: "manual"`,
      8 KiB read limit); classification exactly as `classifyResponse`.
- [ ] Primary-consistent, level-triggered reconciler (Cron Trigger and
      `scheduled` handler) for R3a and R4–R6, plus nonce purging.
- [ ] Observed `ownerBound` with its time, the §13.1 needs-attention flags,
      and the §13.5 R6 confirmation step.
- [ ] Write-before-send: no delivery path exists without the journal row
      (RC6).

### Security boundary

- [ ] Signing seed `PROVISIONING_SIGNING_KEY` (32 bytes, base64url) is a
      per-environment Worker secret read through `readSecret`; `keyId` and
      `PROVISIONING_ISSUER` (`https://` even in development) are non-secret
      variables. Local development uses `.dev.vars` and test keys only.
- [ ] The bundle secret scan is extended to the new names before any secret
      exists.
- [ ] A Cloudflare Access service token, if a harness sits behind a tunnel,
      is a separate Worker secret sent only to that harness's endpoint, and is
      never a provisioning credential.
- [ ] Web holds no Lightagent credential; it trusts only signed-command
      semantics and classifies every response.

### Deployment boundary

- [ ] No `wrangler d1 migrations apply --remote`, no `wrangler secret put`
      and no `wrangler deploy` to staging or production during W1 work.
      Local D1 (`--local`) and workerd tests only.
- [ ] Production signing key stays empty until approved. Staging comes
      first, after its own approval.
- [ ] Cloudflare-native tooling only (Wrangler, D1, Cron Triggers, Worker
      secrets).

### CI boundary

- [ ] Existing Web gates stay authoritative: `npm run check` (typecheck,
      Vitest `workers`/`static`/`client` projects in the workerd pool, build,
      and the `build` project with the bundle secret scan), plus
      `npm run protocol:fixtures -- check`.
- [ ] The D1 journal and migration are tested in workerd against local D1.
- [ ] No Lightagent build, Rust toolchain or GitHub secret enters Web's
      pipeline. The Web repository has no remote; review stays on local
      branches and git bundles until that changes.
