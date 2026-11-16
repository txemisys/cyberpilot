-- Phase 2 Exposure: isolated durable execution accounting only.
-- No migration activates outbound network operations.
CREATE TABLE "ExposureExecutionLease" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "requestId" VARCHAR(128) NOT NULL,
  "domain" VARCHAR(253) NOT NULL,
  "scheduleId" TEXT NOT NULL,
  "authorizationId" TEXT NOT NULL,
  "authorizationRevision" INTEGER NOT NULL,
  "grantId" VARCHAR(128) NOT NULL,
  "consentDigest" VARCHAR(64) NOT NULL,
  "scopeDigest" VARCHAR(64) NOT NULL,
  "state" VARCHAR(24) NOT NULL DEFAULT 'DENIED',
  "reservedDns" INTEGER NOT NULL DEFAULT 0,
  "reservedTls" INTEGER NOT NULL DEFAULT 0,
  "reservedHttp" INTEGER NOT NULL DEFAULT 0,
  "usedDns" INTEGER NOT NULL DEFAULT 0,
  "usedTls" INTEGER NOT NULL DEFAULT 0,
  "usedHttp" INTEGER NOT NULL DEFAULT 0,
  "maxTotal" INTEGER NOT NULL DEFAULT 0,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "finishedAt" TIMESTAMP(3),
  "denialCode" VARCHAR(80),
  "issuedById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ExposureExecutionLease_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExposureExecutionLease_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
      ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposureExecutionLease_nonnegative_check" CHECK (
    "reservedDns" >= 0 AND "reservedDns" <= 8
    AND "reservedTls" >= 0 AND "reservedTls" <= 1
    AND "reservedHttp" >= 0 AND "reservedHttp" <= 1
    AND "usedDns" >= 0 AND "usedDns" <= "reservedDns"
    AND "usedTls" >= 0 AND "usedTls" <= "reservedTls"
    AND "usedHttp" >= 0 AND "usedHttp" <= "reservedHttp"
    AND "maxTotal" >= 0 AND "maxTotal" <= 10
    AND "reservedDns" + "reservedTls" + "reservedHttp" <= "maxTotal"
  ),
  CONSTRAINT "ExposureExecutionLease_state_check" CHECK (
    "state" IN ('DENIED', 'ACTIVE', 'CANCELLED', 'EXPIRED',
                'COMPLETED', 'FAILED')
  )
);
CREATE TABLE "ExposureExecutionCharge" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "leaseId" TEXT NOT NULL,
  "sequence" INTEGER NOT NULL,
  "source" VARCHAR(24) NOT NULL,
  "status" VARCHAR(24) NOT NULL DEFAULT 'RESERVED',
  "targetDigest" VARCHAR(64) NOT NULL,
  "resultDigest" VARCHAR(64),
  "peerDigest" VARCHAR(64),
  "errorCode" VARCHAR(80),
  "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "finishedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ExposureExecutionCharge_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExposureExecutionCharge_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
      ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposureExecutionCharge_leaseId_fkey"
    FOREIGN KEY ("leaseId") REFERENCES "ExposureExecutionLease"("id")
      ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposureExecutionCharge_sequence_check" CHECK ("sequence" >= 1),
  CONSTRAINT "ExposureExecutionCharge_source_check" CHECK (
    "source" IN ('DNS', 'TLS_HANDSHAKE', 'HTTPS_HEADERS')),
  CONSTRAINT "ExposureExecutionCharge_status_check" CHECK (
    "status" IN ('RESERVED','OBSERVED','UNKNOWN','ERROR','DENIED'))
);
CREATE UNIQUE INDEX "ExposureExecutionLease_organizationId_requestId_key"
  ON "ExposureExecutionLease"("organizationId", "requestId");
CREATE INDEX "ExposureExecutionLease_organizationId_domain_state_idx"
  ON "ExposureExecutionLease"("organizationId", "domain", "state");
CREATE INDEX "ExposureExecutionLease_organizationId_expiresAt_idx"
  ON "ExposureExecutionLease"("organizationId", "expiresAt");
CREATE INDEX "ExposureExecutionLease_scheduleId_state_idx"
  ON "ExposureExecutionLease"("scheduleId", "state");
CREATE INDEX "ExposureExecutionLease_authorizationId_authorizationRevision_idx"
  ON "ExposureExecutionLease"("authorizationId", "authorizationRevision");
CREATE UNIQUE INDEX "ExposureExecutionCharge_leaseId_sequence_key"
  ON "ExposureExecutionCharge"("leaseId", "sequence");
CREATE INDEX "ExposureExecutionCharge_organizationId_leaseId_status_idx"
  ON "ExposureExecutionCharge"("organizationId", "leaseId", "status");
CREATE INDEX "ExposureExecutionCharge_organizationId_createdAt_idx"
  ON "ExposureExecutionCharge"("organizationId", "createdAt");
