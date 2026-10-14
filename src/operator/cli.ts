/**
 * Operator command parsing and dispatch. Pure: it takes a database and an
 * output sink, so tests run it inside workerd against the test D1. The Node
 * entry point (main.ts) supplies the real staging database.
 *
 * Output is one JSON document per command: sanitized results or an error
 * code with a short message. Never emails, tokens, or credential data.
 */
import { operatorActor, OperatorAuthorizationError, type Actor } from "./actors";
import { OperatorError, OperatorService, STATUS_OPERATIONS, type StatusOperation } from "./service";

export const USAGE = `usage: npm run operator -- <command> --env staging [options]

  show-user        --user usr_…                         status, sign-in methods, counts
  list-passkeys    --user usr_…                         passkey ids, labels, fingerprints
  approve          --user usr_… --reason "…"            pending   → active
  suspend          --user usr_… --reason "…"            active    → suspended
  reactivate       --user usr_… --reason "…"            suspended → active
  disable          --user usr_… --reason "…"            pending/active/suspended → disabled
  revoke-sessions  --user usr_… --reason "…"            delete all of one user's sessions
  revoke-all-sessions --reason "…" --yes                delete every session (incident)
  remove-passkey   --user usr_… --passkey <id> --reason "…"
  purge-verifications [--limit N]                       delete expired OAuth state/passkey challenges

  provisioning-attention [--harness hns_…] [--limit N]  provisioning jobs that need an operator
  retire-harness   --harness hns_… --code CODE --reason "…" --yes
                                                        retire a harness id for good (CODE: LEDGER_CONTINUITY_FAILED,
                                                        LEDGER_LOST, DECOMMISSIONED)
  approve-harness-replacement --retired hns_… --replacement hns_… --reason "…" --yes
  release-harness-hold --harness hns_… --reason "…"     lift a LEDGER_CONTINUITY_FAILED circuit break

  The operator id comes from --operator opr_… or LIGHTAGENT_OPERATOR_ID.
  Every change is one transaction with an admin.* audit event.`;

export interface Output {
  out(text: string): void;
  err(text: string): void;
}

const VALUE_FLAGS = new Set(["user", "reason", "passkey", "operator", "env", "limit", "operation", "harness", "code", "retired", "replacement"]);
const BOOLEAN_FLAGS = new Set(["yes"]);

export interface ParsedArgs {
  command: string | undefined;
  flags: Record<string, string>;
  switches: Set<string>;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const flags: Record<string, string> = {};
  const switches = new Set<string>();
  let command: string | undefined;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? "";
    if (arg.startsWith("--")) {
      const [name = "", inline] = arg.slice(2).split("=", 2);
      if (BOOLEAN_FLAGS.has(name)) switches.add(name);
      else if (VALUE_FLAGS.has(name)) {
        const value = inline ?? argv[(i += 1)];
        if (value === undefined) throw new OperatorError("INVALID_INPUT", `--${name} needs a value`);
        flags[name] = value;
      } else throw new OperatorError("INVALID_INPUT", `unknown option --${name}`);
    } else if (command === undefined) command = arg;
    else throw new OperatorError("INVALID_INPUT", `unexpected argument ${arg}`);
  }
  return { command, flags, switches };
}

/** Run one command; returns the process exit code. */
export async function runOperatorCommand(args: ParsedArgs, db: D1Database, io: Output, operatorId: string | undefined): Promise<number> {
  const print = (value: unknown) => io.out(JSON.stringify(value, null, 2));
  try {
    const { command, flags, switches } = args;
    if (!command || command === "help") {
      io.out(USAGE);
      return command ? 0 : 2;
    }
    const service = new OperatorService(db);
    const actor: Actor = operatorActor(flags["operator"] ?? operatorId);
    const base = { userId: flags["user"] ?? "", reason: flags["reason"] ?? "", ...(flags["operation"] ? { operationId: flags["operation"] } : {}) };

    if (command in STATUS_OPERATIONS) {
      print({ ok: true, result: await service.changeStatus(actor, command as StatusOperation, base) });
    } else if (command === "show-user") {
      print({ ok: true, result: await service.describeUser(actor, flags["user"] ?? "") });
    } else if (command === "list-passkeys") {
      print({ ok: true, result: await service.listPasskeys(actor, flags["user"] ?? "") });
    } else if (command === "revoke-sessions") {
      print({ ok: true, result: await service.revokeUserSessions(actor, base) });
    } else if (command === "revoke-all-sessions") {
      print({ ok: true, result: await service.revokeAllSessions(actor, { reason: base.reason, confirm: switches.has("yes"), ...(base.operationId ? { operationId: base.operationId } : {}) }) });
    } else if (command === "remove-passkey") {
      print({ ok: true, result: await service.removePasskey(actor, { ...base, passkeyId: flags["passkey"] ?? "" }) });
    } else if (command === "provisioning-attention") {
      const limit = flags["limit"] === undefined ? undefined : Number(flags["limit"]);
      if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) throw new OperatorError("INVALID_INPUT", "--limit must be a positive integer");
      print({ ok: true, result: await service.provisioningAttention(actor, { ...(flags["harness"] ? { harnessId: flags["harness"] } : {}), ...(limit === undefined ? {} : { limit }) }) });
    } else if (command === "retire-harness") {
      print({ ok: true, result: await service.retireHarness(actor, { harnessId: flags["harness"] ?? "", reasonCode: flags["code"] ?? "", reason: base.reason, confirm: switches.has("yes"), ...(base.operationId ? { operationId: base.operationId } : {}) }) });
    } else if (command === "approve-harness-replacement") {
      print({
        ok: true,
        result: await service.approveHarnessReplacement(actor, {
          retiredHarnessId: flags["retired"] ?? "",
          replacementHarnessId: flags["replacement"] ?? "",
          reason: base.reason,
          confirm: switches.has("yes"),
          ...(base.operationId ? { operationId: base.operationId } : {}),
        }),
      });
    } else if (command === "release-harness-hold") {
      print({ ok: true, result: await service.releaseHarnessHold(actor, { harnessId: flags["harness"] ?? "", reason: base.reason, ...(base.operationId ? { operationId: base.operationId } : {}) }) });
    } else if (command === "purge-verifications") {
      const limit = flags["limit"] === undefined ? undefined : Number(flags["limit"]);
      if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) throw new OperatorError("INVALID_INPUT", "--limit must be a positive integer");
      print({ ok: true, result: await service.purgeExpiredVerifications(actor, limit === undefined ? {} : { limit }) });
    } else {
      throw new OperatorError("INVALID_INPUT", `unknown command ${command}`);
    }
    return 0;
  } catch (error) {
    if (error instanceof OperatorError || error instanceof OperatorAuthorizationError) {
      io.err(JSON.stringify({ ok: false, error: { code: error instanceof OperatorError ? error.code : "FORBIDDEN", message: error.message } }));
      return 1;
    }
    // Unexpected (database) failure: name only; D1 text can contain SQL or values.
    io.err(JSON.stringify({ ok: false, error: { code: "INTERNAL_ERROR", message: error instanceof Error ? error.name : "error" } }));
    return 1;
  }
}
