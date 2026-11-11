-- Witnessed offline checklist; never a provider attestation or an automatic merge authorization.
CREATE TABLE "AssetOfflineAcceptanceRun" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "importId" TEXT NOT NULL,
  "inspectionId" TEXT NOT NULL,
  "idempotencyKey" TEXT NOT NULL,
  "dossierDigest" VARCHAR(64) NOT NULL,
  "sourceDigest" VARCHAR(64) NOT NULL,
  "state" TEXT NOT NULL DEFAULT 'DRAFT',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "operatorUserId" TEXT NOT NULL,
  "openingReason" TEXT NOT NULL,
  "steps" JSONB NOT NULL,
  "limitations" JSONB NOT NULL,
  "humanAcknowledgements" JSONB NOT NULL,
  "completedSteps" INTEGER NOT NULL DEFAULT 0,
  "blockedSteps" INTEGER NOT NULL DEFAULT 0,
  "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "submittedAt" TIMESTAMP(3),
  "submittedByUserId" TEXT,
  "submittedReason" TEXT,
  CONSTRAINT "AssetOfflineAcceptanceRun_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetOfflineAcceptanceRun_revision_check" CHECK ("revision" >= 1),
  CONSTRAINT "AssetOfflineAcceptanceRun_counts_check" CHECK
    ("completedSteps" >= 0 AND "blockedSteps" >= 0 AND
      "completedSteps" + "blockedSteps" <= 9),
  CONSTRAINT "AssetOfflineAcceptanceRun_state_check" CHECK
    ("state" IN ('DRAFT','IN_PROGRESS','BLOCKED','EVIDENCE_CAPTURED','REOPENED'))
);
CREATE UNIQUE INDEX "AssetOfflineAcceptanceRun_organizationId_idempotencyKey_key"
  ON "AssetOfflineAcceptanceRun"("organizationId","idempotencyKey");
CREATE INDEX "AssetOfflineAcceptanceRun_organizationId_importId_inspectionId_idx"
  ON "AssetOfflineAcceptanceRun"("organizationId","importId","inspectionId");
CREATE INDEX "AssetOfflineAcceptanceRun_organizationId_state_updatedAt_idx"
  ON "AssetOfflineAcceptanceRun"("organizationId","state","updatedAt");
ALTER TABLE "AssetOfflineAcceptanceRun"
  ADD CONSTRAINT "AssetOfflineAcceptanceRun_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
