/**
 * Registered Lightagent harnesses. Administrator-controlled data only: no
 * user-facing route may write here, and endpoints never come from user input
 * (SSRF protection). No private keys or overlay-network credentials.
 */
import { z } from "../../shared/zod";
import type { Environment } from "../config/config";
import { randomId } from "../utils/random";
import { type Clock, NameSchema, NullableTimestamp, parseRow, type RepositoryOptions, systemClock, Timestamp, idSchema } from "./common";
import { ConstraintViolationError, guard, NotFoundError } from "./errors";
import { decodeJson, encodeJson, HarnessCapabilitiesSchema, JSON_LIMITS, type HarnessCapabilities } from "./json";

export const HARNESS_STATUSES = ["active", "draining", "disabled"] as const;
export type HarnessStatus = (typeof HARNESS_STATUSES)[number];

const HarnessRow = z.object({
  id: idSchema("hns"),
  name: z.string().min(1).max(80),
  environment: z.enum(["development", "staging", "production"]),
  endpoint: z.string().min(10).max(2048),
  key_id: z.string().min(1).max(64),
  public_key: z.string().length(44).nullable(),
  status: z.enum(HARNESS_STATUSES),
  capabilities_json: z.string(),
  created_at: Timestamp,
  updated_at: Timestamp,
  last_seen_at: NullableTimestamp,
});

export interface Harness {
  id: string;
  name: string;
  environment: Environment;
  endpoint: string;
  keyId: string;
  publicKey: string | null;
  status: HarnessStatus;
  capabilities: HarnessCapabilities;
  createdAt: number;
  updatedAt: number;
  lastSeenAt: number | null;
}

function toHarness(row: unknown): Harness {
  const r = parseRow(HarnessRow, row);
  return {
    id: r.id,
    name: r.name,
    environment: r.environment,
    endpoint: r.endpoint,
    keyId: r.key_id,
    publicKey: r.public_key,
    status: r.status,
    capabilities: decodeJson(HarnessCapabilitiesSchema, r.capabilities_json),
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    lastSeenAt: r.last_seen_at,
  };
}

/**
 * Validate an administrator-supplied endpoint: an absolute https URL with no
 * credentials, query, or fragment (http only for development harnesses).
 */
export function normalizeHarnessEndpoint(raw: string, environment: Environment): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConstraintViolationError("check");
  }
  const schemeOk = url.protocol === "https:" || (url.protocol === "http:" && environment === "development");
  if (!schemeOk || url.username || url.password || url.search || url.hash) {
    throw new ConstraintViolationError("check");
  }
  return url.href.replace(/\/$/, "");
}

const KeyId = z.string().regex(/^[A-Za-z0-9._-]{1,64}$/);
const PublicKey = z.string().regex(/^[A-Za-z0-9+/]{43}=$/); // 32-byte Ed25519, base64

export interface RegisterHarnessInput {
  name: string;
  environment: Environment;
  endpoint: string;
  keyId: string;
  publicKey?: string | null;
  capabilities: HarnessCapabilities;
}

/** Trusted/admin repository. Registration is an administrator operation. */
export class HarnessRepository {
  private readonly now: Clock;

  constructor(
    private readonly db: D1Database,
    options: RepositoryOptions = {},
  ) {
    this.now = options.now ?? systemClock;
  }

  /** Register a harness in `disabled` state; an admin activates it explicitly. */
  async registerAdmin(input: RegisterHarnessInput): Promise<Harness> {
    const name = NameSchema.parse(input.name);
    const endpoint = normalizeHarnessEndpoint(input.endpoint, input.environment);
    const keyId = KeyId.parse(input.keyId);
    const publicKey = input.publicKey == null ? null : PublicKey.parse(input.publicKey);
    const capabilities = encodeJson(HarnessCapabilitiesSchema, input.capabilities, JSON_LIMITS.capabilities);
    const now = this.now();
    const row = await guard(() =>
      this.db
        .prepare(
          `INSERT INTO harnesses (id, name, environment, endpoint, key_id, public_key, status, capabilities_json, created_at, updated_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'disabled', ?7, ?8, ?8) RETURNING *`,
        )
        .bind(randomId("hns"), name, input.environment, endpoint, keyId, publicKey, capabilities, now)
        .first(),
    );
    return toHarness(row);
  }

  async getById(harnessId: string): Promise<Harness | null> {
    const row = await guard(() => this.db.prepare(`SELECT * FROM harnesses WHERE id = ?1`).bind(harnessId).first());
    return row ? toHarness(row) : null;
  }

  /** Active harnesses for this Worker's environment only. */
  async listActive(environment: Environment): Promise<Harness[]> {
    const { results } = await guard(() =>
      this.db
        .prepare(`SELECT * FROM harnesses WHERE environment = ?1 AND status = 'active' ORDER BY created_at, id`)
        .bind(environment)
        .all(),
    );
    return results.map(toHarness);
  }

  async setStatusAdmin(harnessId: string, status: HarnessStatus): Promise<Harness> {
    const row = await guard(() =>
      this.db
        .prepare(`UPDATE harnesses SET status = ?1, updated_at = ?2 WHERE id = ?3 RETURNING *`)
        .bind(status, this.now(), harnessId)
        .first(),
    );
    if (!row) throw new NotFoundError("harness");
    return toHarness(row);
  }
}
