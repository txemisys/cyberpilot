CREATE TABLE "AssetOsvQuotaDay" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "utcDay" DATE NOT NULL,
  "inspectionLimit" INTEGER NOT NULL DEFAULT 20,
  "requestLimit" INTEGER NOT NULL DEFAULT 200,
  "inspectionsReserved" INTEGER NOT NULL DEFAULT 0,
  "requestsReserved" INTEGER NOT NULL DEFAULT 0,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AssetOsvQuotaDay_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetOsvQuotaDay_positive_limits" CHECK ("inspectionLimit" > 0 AND "requestLimit" > 0),
  CONSTRAINT "AssetOsvQuotaDay_nonnegative_counters" CHECK ("inspectionsReserved" >= 0 AND "requestsReserved" >= 0),
  CONSTRAINT "AssetOsvQuotaDay_counters_bounded" CHECK ("inspectionsReserved" <= "inspectionLimit" AND "requestsReserved" <= "requestLimit")
);
CREATE TABLE "AssetOsvQuotaReservation" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "quotaDayId" TEXT NOT NULL,
  "requestKey" TEXT NOT NULL,
  "requestDigest" VARCHAR(64) NOT NULL,
  "inventoryImportId" TEXT NOT NULL,
  "reservedRequests" INTEGER NOT NULL,
  "state" TEXT NOT NULL DEFAULT 'RESERVED',
  "actualRequests" INTEGER NOT NULL DEFAULT 0,
  "errorCode" TEXT,
  "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "finishedAt" TIMESTAMP(3),
  CONSTRAINT "AssetOsvQuotaReservation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetOsvQuotaReservation_valid_state" CHECK ("state" IN ('RESERVED', 'FINISHED', 'FAILED', 'UNKNOWN')),
  CONSTRAINT "AssetOsvQuotaReservation_counts_bounded" CHECK ("reservedRequests" > 0 AND "actualRequests" >= 0 AND "actualRequests" <= "reservedRequests")
);
CREATE UNIQUE INDEX "AssetOsvQuotaDay_organizationId_utcDay_key"
  ON "AssetOsvQuotaDay"("organizationId", "utcDay");
CREATE INDEX "AssetOsvQuotaDay_organizationId_updatedAt_idx"
  ON "AssetOsvQuotaDay"("organizationId", "updatedAt");
CREATE UNIQUE INDEX "AssetOsvQuotaReservation_organizationId_requestKey_key"
  ON "AssetOsvQuotaReservation"("organizationId", "requestKey");
CREATE INDEX "AssetOsvQuotaReservation_organizationId_startedAt_idx"
  ON "AssetOsvQuotaReservation"("organizationId", "startedAt");
CREATE INDEX "AssetOsvQuotaReservation_quotaDayId_state_idx"
  ON "AssetOsvQuotaReservation"("quotaDayId", "state");
ALTER TABLE "AssetOsvQuotaDay" ADD CONSTRAINT "AssetOsvQuotaDay_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvQuotaReservation" ADD CONSTRAINT "AssetOsvQuotaReservation_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AssetOsvQuotaReservation" ADD CONSTRAINT "AssetOsvQuotaReservation_quotaDayId_fkey"
  FOREIGN KEY ("quotaDayId") REFERENCES "AssetOsvQuotaDay"("id") ON DELETE CASCADE ON UPDATE CASCADE;
