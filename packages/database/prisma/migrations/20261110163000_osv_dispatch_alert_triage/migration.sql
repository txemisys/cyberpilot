CREATE TABLE "AssetOsvDispatchAlert" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "code" VARCHAR(80) NOT NULL,
 "subjectKey" VARCHAR(100) NOT NULL,
 "severity" TEXT NOT NULL,
 "state" TEXT NOT NULL DEFAULT 'OPEN',
 "revision" INTEGER NOT NULL DEFAULT 1,
 "firstSeenAt" TIMESTAMP(3) NOT NULL,
 "lastSeenAt" TIMESTAMP(3) NOT NULL,
 "observedCount" INTEGER NOT NULL DEFAULT 1,
 "evidenceDigest" VARCHAR(64) NOT NULL,
 "evidence" JSONB NOT NULL,
 "acknowledgementReason" TEXT,
 "acknowledgedByUserId" TEXT,
 "acknowledgedAt" TIMESTAMP(3),
 "resolutionReason" TEXT,
 "resolvedByUserId" TEXT,
 "resolvedAt" TIMESTAMP(3),
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "AssetOsvDispatchAlert_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "AssetOsvDispatchAlert_state_check" CHECK ("state" IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
 CONSTRAINT "AssetOsvDispatchAlert_severity_check" CHECK ("severity" IN ('WARNING','CRITICAL')),
 CONSTRAINT "AssetOsvDispatchAlert_revision_check" CHECK ("revision" >= 1),
 CONSTRAINT "AssetOsvDispatchAlert_count_check" CHECK ("observedCount" >= 1)
);
CREATE UNIQUE INDEX "AssetOsvDispatchAlert_organizationId_code_subjectKey_key"
 ON "AssetOsvDispatchAlert"("organizationId","code","subjectKey");
CREATE INDEX "AssetOsvDispatchAlert_organizationId_state_lastSeenAt_idx"
 ON "AssetOsvDispatchAlert"("organizationId","state","lastSeenAt");
CREATE INDEX "AssetOsvDispatchAlert_organizationId_severity_lastSeenAt_idx"
 ON "AssetOsvDispatchAlert"("organizationId","severity","lastSeenAt");
CREATE INDEX "AssetOsvDispatchAlert_organizationId_createdAt_idx"
 ON "AssetOsvDispatchAlert"("organizationId","createdAt");
ALTER TABLE "AssetOsvDispatchAlert" ADD CONSTRAINT "AssetOsvDispatchAlert_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
 ON DELETE CASCADE ON UPDATE CASCADE;
