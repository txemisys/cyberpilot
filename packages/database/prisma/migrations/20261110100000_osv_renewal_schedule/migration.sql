CREATE TABLE "AssetOsvRenewalSchedule" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "inventoryImportId" TEXT NOT NULL,
  "sourceInspectionId" TEXT NOT NULL,
  "createdByUserId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT FALSE,
  "cadenceMinutes" INTEGER NOT NULL,
  "nextDueAt" TIMESTAMP(3) NOT NULL,
  "policy" JSONB NOT NULL,
  "inspection" JSONB NOT NULL,
  "allowNewPackages" BOOLEAN NOT NULL DEFAULT FALSE,
  "allowIncompleteInventory" BOOLEAN NOT NULL DEFAULT FALSE,
  "outboundConsent" BOOLEAN NOT NULL DEFAULT FALSE,
  "consentedAt" TIMESTAMP(3),
  "consentDigest" VARCHAR(64) NOT NULL,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "lastAttemptAt" TIMESTAMP(3),
  "lastSucceededAt" TIMESTAMP(3),
  "lastRunId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AssetOsvRenewalSchedule_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetOsvRenewalSchedule_cadence_bounds" CHECK ("cadenceMinutes" BETWEEN 60 AND 43200),
  CONSTRAINT "AssetOsvRenewalSchedule_revision_positive" CHECK ("revision" > 0),
  CONSTRAINT "AssetOsvRenewalSchedule_consent_guard" CHECK (
    NOT "enabled" OR ("outboundConsent" = TRUE AND "consentedAt" IS NOT NULL))
);
CREATE TABLE "AssetOsvRenewalRun" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "scheduleId" TEXT NOT NULL,
  "slotAt" TIMESTAMP(3) NOT NULL,
  "state" TEXT NOT NULL DEFAULT 'CLAIMED',
  "commandDigest" VARCHAR(64) NOT NULL,
  "claimToken" VARCHAR(64) NOT NULL,
  "claimExpiresAt" TIMESTAMP(3) NOT NULL,
  "requestedByUserId" TEXT,
  "inspectionId" TEXT,
  "result" JSONB,
  "errorCode" TEXT,
  "claimedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completedAt" TIMESTAMP(3),
  CONSTRAINT "AssetOsvRenewalRun_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetOsvRenewalRun_states" CHECK ("state" IN (
    'CLAIMED', 'COMPLETE', 'BLOCKED', 'FAILED', 'UNKNOWN'
  ))
);
CREATE INDEX "AssetOsvRenewalSchedule_organizationId_enabled_nextDueAt_idx"
  ON "AssetOsvRenewalSchedule"("organizationId", "enabled", "nextDueAt");
CREATE INDEX "AssetOsvRenewalSchedule_organizationId_inventoryImportId_idx"
  ON "AssetOsvRenewalSchedule"("organizationId", "inventoryImportId");
CREATE UNIQUE INDEX "AssetOsvRenewalRun_scheduleId_slotAt_key"
  ON "AssetOsvRenewalRun"("scheduleId", "slotAt");
CREATE INDEX "AssetOsvRenewalRun_organizationId_state_claimedAt_idx"
  ON "AssetOsvRenewalRun"("organizationId", "state", "claimedAt");
CREATE INDEX "AssetOsvRenewalRun_organizationId_scheduleId_slotAt_idx"
  ON "AssetOsvRenewalRun"("organizationId", "scheduleId", "slotAt");
ALTER TABLE "AssetOsvRenewalSchedule" ADD CONSTRAINT "AssetOsvRenewalSchedule_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvRenewalSchedule" ADD CONSTRAINT "AssetOsvRenewalSchedule_inventoryImportId_fkey"
  FOREIGN KEY ("inventoryImportId") REFERENCES "AssetInventoryImport"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvRenewalRun" ADD CONSTRAINT "AssetOsvRenewalRun_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvRenewalRun" ADD CONSTRAINT "AssetOsvRenewalRun_scheduleId_fkey"
  FOREIGN KEY ("scheduleId") REFERENCES "AssetOsvRenewalSchedule"("id") ON DELETE CASCADE ON UPDATE CASCADE;
