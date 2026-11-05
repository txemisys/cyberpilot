CREATE TABLE "AssetOsvInspection" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "inventoryImportId" TEXT NOT NULL,
  "actorUserId" TEXT,
  "requestKey" TEXT NOT NULL,
  "requestDigest" VARCHAR(64) NOT NULL,
  "reportDigest" VARCHAR(64) NOT NULL,
  "status" TEXT NOT NULL,
  "provider" TEXT NOT NULL DEFAULT 'OSV_DEV_API',
  "coverage" TEXT NOT NULL DEFAULT 'DECLARED_NOT_VERIFIED',
  "report" JSONB NOT NULL,
  "queryCount" INTEGER NOT NULL,
  "completedCount" INTEGER NOT NULL,
  "possibleCount" INTEGER NOT NULL,
  "providerOnlyCount" INTEGER NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "completedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AssetOsvInspection_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "AssetOsvQueryRecord" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "inspectionId" TEXT NOT NULL,
  "queryKey" VARCHAR(64) NOT NULL,
  "ecosystem" TEXT NOT NULL,
  "packageName" TEXT NOT NULL,
  "version" TEXT NOT NULL,
  "providerStatus" TEXT NOT NULL,
  "providerDigest" VARCHAR(64),
  "checkedAt" TIMESTAMP(3),
  "possibleIds" JSONB NOT NULL DEFAULT '[]',
  "providerOnlyIds" JSONB NOT NULL DEFAULT '[]',
  "withdrawnIds" JSONB NOT NULL DEFAULT '[]',
  "unresolvedIds" JSONB NOT NULL DEFAULT '[]',
  "observationCount" INTEGER NOT NULL,
  "pageCount" INTEGER NOT NULL,
  "recordedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AssetOsvQueryRecord_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "AssetOsvInspection_organizationId_requestKey_key"
  ON "AssetOsvInspection"("organizationId", "requestKey");
CREATE INDEX "AssetOsvInspection_organizationId_createdAt_idx"
  ON "AssetOsvInspection"("organizationId", "createdAt");
CREATE INDEX "AssetOsvInspection_organizationId_inventoryImportId_createdAt_idx"
  ON "AssetOsvInspection"("organizationId", "inventoryImportId", "createdAt");
CREATE UNIQUE INDEX "AssetOsvQueryRecord_inspectionId_queryKey_key"
  ON "AssetOsvQueryRecord"("inspectionId", "queryKey");
CREATE INDEX "AssetOsvQueryRecord_organizationId_ecosystem_packageName_version_idx"
  ON "AssetOsvQueryRecord"("organizationId", "ecosystem", "packageName", "version");
CREATE INDEX "AssetOsvQueryRecord_organizationId_inspectionId_idx"
  ON "AssetOsvQueryRecord"("organizationId", "inspectionId");
ALTER TABLE "AssetOsvInspection" ADD CONSTRAINT "AssetOsvInspection_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvInspection" ADD CONSTRAINT "AssetOsvInspection_inventoryImportId_fkey"
  FOREIGN KEY ("inventoryImportId") REFERENCES "AssetInventoryImport"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvQueryRecord" ADD CONSTRAINT "AssetOsvQueryRecord_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvQueryRecord" ADD CONSTRAINT "AssetOsvQueryRecord_inspectionId_fkey"
  FOREIGN KEY ("inspectionId") REFERENCES "AssetOsvInspection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
