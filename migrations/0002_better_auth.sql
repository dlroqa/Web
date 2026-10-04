-- Migration 0002: Better Auth core schema + passkey plugin (better-auth 1.7.7,
-- @better-auth/passkey 1.7.7).
--
-- Generated with `npm run auth:schema -- generate` from the Worker's exact
-- auth options, then reviewed. Column names, types, and the indexes Better
-- Auth expects are unchanged (so `npm run auth:schema -- check` and the
-- schema drift test pass); the review added the hardening marked HARDENING.
--
-- Better Auth owns these tables (authentication only). Application identity,
-- ownership, policy, and revocation live in 0001's tables and reference the
-- auth user only through user_profiles.auth_user_id (opaque, no FK).
--
-- Not STRICT: Better Auth declares timestamps with the `date` type, which
-- STRICT tables do not allow.

CREATE TABLE "user" (
  "id"            text    NOT NULL PRIMARY KEY,
  "name"          text    NOT NULL,
  "email"         text    NOT NULL UNIQUE,
  "emailVerified" integer NOT NULL,
  "image"         text,
  "createdAt"     date    NOT NULL,
  "updatedAt"     date    NOT NULL,
  -- HARDENING: bound provider-supplied profile data.
  CHECK (length("id") BETWEEN 1 AND 255),
  CHECK (length("name") <= 512),
  CHECK (length("email") BETWEEN 3 AND 320),
  CHECK ("image" IS NULL OR length("image") <= 4096)
);

CREATE TABLE "session" (
  "id"        text NOT NULL PRIMARY KEY,
  "expiresAt" date NOT NULL,
  "token"     text NOT NULL UNIQUE,
  "createdAt" date NOT NULL,
  "updatedAt" date NOT NULL,
  "ipAddress" text,
  "userAgent" text,
  "userId"    text NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  -- HARDENING: raw client IPs are never stored. With ipAddress tracking
  -- disabled Better Auth writes '' here; the database refuses anything else.
  CHECK ("ipAddress" IS NULL OR "ipAddress" = ''),
  CHECK ("userAgent" IS NULL OR length("userAgent") <= 4096)
);

CREATE TABLE "account" (
  "id"                    text NOT NULL PRIMARY KEY,
  "accountId"             text NOT NULL,
  "providerId"            text NOT NULL,
  "userId"                text NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "accessToken"           text,
  "refreshToken"          text,
  "idToken"               text,
  "accessTokenExpiresAt"  date,
  "refreshTokenExpiresAt" date,
  "scope"                 text,
  "password"              text,
  "createdAt"             date NOT NULL,
  "updatedAt"             date NOT NULL,
  -- HARDENING: only the enabled sign-in providers, and no password accounts
  -- (password sign-in is disabled; nothing may store a password hash).
  CHECK ("providerId" IN ('google', 'github')),
  CHECK ("password" IS NULL),
  CHECK (length("accountId") BETWEEN 1 AND 255)
);

CREATE TABLE "verification" (
  "id"         text NOT NULL PRIMARY KEY,
  "identifier" text NOT NULL,
  "value"      text NOT NULL,
  "expiresAt"  date NOT NULL,
  "createdAt"  date NOT NULL,
  "updatedAt"  date NOT NULL,
  CHECK (length("identifier") <= 1024),
  CHECK (length("value") <= 16384)
);

CREATE TABLE "passkey" (
  "id"           text    NOT NULL PRIMARY KEY,
  "name"         text,
  "publicKey"    text    NOT NULL,
  "userId"       text    NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "credentialID" text    NOT NULL,
  "counter"      integer NOT NULL,
  "deviceType"   text    NOT NULL,
  "backedUp"     integer NOT NULL,
  "transports"   text,
  "createdAt"    date,
  "aaguid"       text,
  CHECK ("name" IS NULL OR length("name") <= 80),
  CHECK (length("publicKey") <= 4096),
  CHECK (length("credentialID") BETWEEN 1 AND 2048),
  CHECK ("transports" IS NULL OR length("transports") <= 256),
  CHECK ("aaguid" IS NULL OR length("aaguid") <= 64)
);

CREATE INDEX "session_userId_idx" ON "session" ("userId");
CREATE INDEX "account_userId_idx" ON "account" ("userId");
CREATE INDEX "verification_identifier_idx" ON "verification" ("identifier");
CREATE INDEX "passkey_userId_idx" ON "passkey" ("userId");

-- HARDENING: a credential id identifies exactly one passkey (Better Auth's
-- generated index is non-unique; same name, now unique).
CREATE UNIQUE INDEX "passkey_credentialID_idx" ON "passkey" ("credentialID");

-- HARDENING: one provider identity maps to exactly one auth user, so a
-- Google/GitHub account can never be attached to two users.
CREATE UNIQUE INDEX "account_provider_identity_idx" ON "account" ("providerId", "accountId");
