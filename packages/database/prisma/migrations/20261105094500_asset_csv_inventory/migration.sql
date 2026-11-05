CREATE TYPE "AssetImportState" AS ENUM ('COMMITTED', 'RETIRED');

CREATE TABLE "AssetInventoryImport" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "actorUserId" TEXT,
  "idempotencyKey" TEXT NOT NULL,
  "payloadDigest" VARCHAR(64) NOT NULL,
  "sourceLabel" TEXT NOT NULL,
  "state" "AssetImportState" NOT NULL DEFAULT 'COMMITTED',
  "schemaVersion" INTEGER NOT NULL DEFAULT 1,
  "declaredCount" INTEGER NOT NULL,
  "importedCount" INTEGER NOT NULL,
  "duplicateCount" INTEGER NOT NULL,
  "unknownVersionCount" INTEGER NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "retiredAt" TIMESTAMP(3),
  CONSTRAINT "AssetInventoryImport_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "AssetInventoryDevice" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "importId" TEXT NOT NULL,
  "externalId" TEXT NOT NULL,
  "hostname" TEXT,
  "ownerHash" VARCHAR(64),
  "platform" TEXT NOT NULL,
  "osName" TEXT NOT NULL,
  "osVersion" TEXT,
  "softwareName" TEXT NOT NULL DEFAULT '',
  "softwareVersion" TEXT,
  "observedAt" TIMESTAMP(3) NOT NULL,
  "sourceRow" INTEGER NOT NULL,
  "normalizedProductKey" TEXT NOT NULL DEFAULT '',
  "versionStatus" TEXT NOT NULL,
  "freshnessStatus" TEXT NOT NULL,
  "advisoryStatus" TEXT NOT NULL,
  "advisoryIds" JSONB NOT NULL DEFAULT '[]',
  "confidence" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AssetInventoryDevice_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "AssetInventoryImport_organizationId_idempotencyKey_key"
  ON "AssetInventoryImport"("organizationId", "idempotencyKey");
CREATE INDEX "AssetInventoryImport_organizationId_createdAt_idx"
  ON "AssetInventoryImport"("organizationId", "createdAt");
CREATE INDEX "AssetInventoryImport_organizationId_state_createdAt_idx"
  ON "AssetInventoryImport"("organizationId", "state", "createdAt");
CREATE UNIQUE INDEX "AssetInventoryDevice_importId_externalId_normalizedProductKey_key"
  ON "AssetInventoryDevice"("importId", "externalId", "normalizedProductKey");
CREATE INDEX "AssetInventoryDevice_organizationId_externalId_observedAt_idx"
  ON "AssetInventoryDevice"("organizationId", "externalId", "observedAt");
CREATE INDEX "AssetInventoryDevice_organizationId_platform_osName_idx"
  ON "AssetInventoryDevice"("organizationId", "platform", "osName");
CREATE INDEX "AssetInventoryDevice_organizationId_importId_idx"
  ON "AssetInventoryDevice"("organizationId", "importId");
ALTER TABLE "AssetInventoryImport" ADD CONSTRAINT "AssetInventoryImport_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetInventoryDevice" ADD CONSTRAINT "AssetInventoryDevice_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetInventoryDevice" ADD CONSTRAINT "AssetInventoryDevice_importId_fkey"
  FOREIGN KEY ("importId") REFERENCES "AssetInventoryImport"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
