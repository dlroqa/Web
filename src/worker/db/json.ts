/**
 * Schemas for every JSON column. Values are validated before they are
 * written and again when read back, and serialized size is bounded to match
 * the CHECK limits in the migration.
 */
import { z } from "../../shared/zod";
import { ConstraintViolationError, UnexpectedDbError } from "./errors";

/** Server-chosen permission ceiling for an agent profile. `admin` can never be granted. */
export const AgentPermissionsSchema = z
  .object({
    chat: z.boolean(),
    memory: z.boolean(),
    rag: z.boolean(),
    web: z.boolean(),
    mcp: z.boolean(),
    shell: z.boolean(),
    admin: z.literal(false),
  })
  .strict();
export type AgentPermissions = z.output<typeof AgentPermissionsSchema>;

/** Least-privilege default for new profiles (MCP/tools need Checkpoint G). */
export const DEFAULT_AGENT_PERMISSIONS: AgentPermissions = Object.freeze({
  chat: true,
  memory: true,
  rag: true,
  web: false,
  mcp: false,
  shell: false,
  admin: false,
});

export const PROVISIONING_OPERATIONS = ["profile.create", "profile.disable", "profile.enable", "profile.revoke"] as const;
export type ProvisioningOperation = (typeof PROVISIONING_OPERATIONS)[number];

export const HarnessCapabilitiesSchema = z
  .object({
    protocolVersions: z.array(z.number().int().min(1).max(100)).min(1).max(8),
    operations: z.array(z.enum(PROVISIONING_OPERATIONS)).max(PROVISIONING_OPERATIONS.length),
    region: z.string().regex(/^[a-z0-9-]{1,32}$/).optional(),
    maxProfiles: z.number().int().min(0).max(1_000_000).optional(),
  })
  .strict();
export type HarnessCapabilities = z.output<typeof HarnessCapabilitiesSchema>;

/** Network identity for audit events: a keyed hash, never a raw IP. */
export const SecurityMetadataSchema = z
  .object({
    sourceHash: z.string().regex(/^[0-9a-f]{64}$/).optional(),
    sourceKeyId: z.string().regex(/^k[0-9]{1,4}$/).optional(),
    country: z.string().regex(/^[A-Z]{2}$/).optional(),
  })
  .strict()
  .refine((m) => (m.sourceHash === undefined) === (m.sourceKeyId === undefined), "sourceHash requires sourceKeyId");
export type SecurityMetadata = z.output<typeof SecurityMetadataSchema>;

export const JSON_LIMITS = {
  permissions: 512,
  capabilities: 2048,
  securityMetadata: 512,
  auditDetails: 4096,
} as const;

/** Validate and serialize; throws ConstraintViolationError when invalid or oversized. */
export function encodeJson<S extends z.ZodType>(schema: S, value: unknown, maxBytes: number): string {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new ConstraintViolationError("check");
  const text = JSON.stringify(parsed.data);
  if (new TextEncoder().encode(text).byteLength > maxBytes) throw new ConstraintViolationError("check");
  return text;
}

/** Parse and validate a stored JSON column. Corrupt data is an internal error. */
export function decodeJson<S extends z.ZodType>(schema: S, text: unknown): z.output<S> {
  if (typeof text !== "string") throw new UnexpectedDbError("stored JSON is not text");
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new UnexpectedDbError("stored JSON is malformed");
  }
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new UnexpectedDbError("stored JSON failed validation");
  return parsed.data;
}
