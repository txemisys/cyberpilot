-- Phase 5: offline Google Workspace LAB-only storage.
-- Tokens, raw emails and Google customer OAuth authorizations are prohibited.
CREATE TABLE "GoogleLabConnection" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "createdById" TEXT NOT NULL,
  "revision" INTEGER NOT NULL DEFAULT 0,
  "state" VARCHAR(40) NOT NULL,
  "stateDigest" VARCHAR(64) NOT NULL,
  "payload" JSONB NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "GoogleLabConnection_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "GoogleLabConnection_organizationId_fkey" FOREIGN KEY
    ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "GoogleLabConnection_revision_nonnegative"
    CHECK ("revision" >= 0),
  CONSTRAINT "GoogleLabConnection_digest_valid"
    CHECK ("stateDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "GoogleLabConnection_state_valid"
    CHECK ("state" IN ('NOT_CONFIGURED','CHALLENGE_ISSUED',
      'CONSENT_DENIED','CONNECTED_LAB','SUSPENDED',
      'REVOKED','EXPIRED'))
);
CREATE UNIQUE INDEX "GoogleLabConnection_organizationId_id_key"
  ON "GoogleLabConnection"("organizationId","id");
CREATE INDEX "GoogleLabConnection_organizationId_state_updatedAt_idx"
  ON "GoogleLabConnection"("organizationId","state","updatedAt");

CREATE TABLE "GoogleLabEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "connectionId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "action" VARCHAR(48) NOT NULL,
  "eventDigest" VARCHAR(64) NOT NULL,
  "connectionDigest" VARCHAR(64) NOT NULL,
  "payload" JSONB NOT NULL,
  "occurredAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "GoogleLabEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "GoogleLabEvent_connection_fkey" FOREIGN KEY
    ("organizationId","connectionId")
    REFERENCES "GoogleLabConnection"("organizationId","id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "GoogleLabEvent_revision_positive"
    CHECK ("revision" >= 1),
  CONSTRAINT "GoogleLabEvent_event_digest_valid"
    CHECK ("eventDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "GoogleLabEvent_connection_digest_valid"
    CHECK ("connectionDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "GoogleLabEvent_organizationId_connectionId_revision_key"
  ON "GoogleLabEvent"("organizationId","connectionId","revision");
CREATE INDEX "GoogleLabEvent_organizationId_connectionId_occurredAt_idx"
  ON "GoogleLabEvent"("organizationId","connectionId","occurredAt");

CREATE TABLE "GoogleEvidenceSnapshot" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "connectionId" TEXT NOT NULL,
  "sourceDigest" VARCHAR(64) NOT NULL,
  "assessmentDigest" VARCHAR(64) NOT NULL,
  "reportDigest" VARCHAR(64) NOT NULL,
  "schemaVersion" INTEGER NOT NULL DEFAULT 1,
  "sourceType" VARCHAR(32) NOT NULL,
  "observedAt" TIMESTAMP(3) NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "assessment" JSONB NOT NULL,
  "report" JSONB NOT NULL,
  "createdById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "GoogleEvidenceSnapshot_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "GoogleEvidenceSnapshot_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
      ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "GoogleEvidenceSnapshot_source_digest_valid"
    CHECK ("sourceDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "GoogleEvidenceSnapshot_assessment_digest_valid"
    CHECK ("assessmentDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "GoogleEvidenceSnapshot_report_digest_valid"
    CHECK ("reportDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "GoogleEvidenceSnapshot_positive_retention"
    CHECK ("expiresAt" > "observedAt"),
  CONSTRAINT "GoogleEvidenceSnapshot_source_offline"
    CHECK ("sourceType" = 'SYNTHETIC_FIXTURE'),
  CONSTRAINT "GoogleEvidenceSnapshot_schema_version_one"
    CHECK ("schemaVersion" = 1)
);
CREATE UNIQUE INDEX "GoogleEvidenceSnapshot_organizationId_connectionId_sourceDigest_key"
  ON "GoogleEvidenceSnapshot"("organizationId","connectionId","sourceDigest");
CREATE INDEX "GoogleEvidenceSnapshot_organizationId_connectionId_observedAt_idx"
  ON "GoogleEvidenceSnapshot"("organizationId","connectionId","observedAt");
CREATE INDEX "GoogleEvidenceSnapshot_organizationId_expiresAt_idx"
  ON "GoogleEvidenceSnapshot"("organizationId","expiresAt");
