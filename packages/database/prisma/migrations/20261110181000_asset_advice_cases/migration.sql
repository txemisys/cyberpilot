CREATE TABLE "AssetAdviceCase" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "importId" TEXT NOT NULL,
  "inspectionId" TEXT NOT NULL,
  "evidenceFingerprint" VARCHAR(64) NOT NULL,
  "inventoryDigest" VARCHAR(64) NOT NULL,
  "inspectionDigest" VARCHAR(64) NOT NULL,
  "externalId" VARCHAR(100) NOT NULL,
  "normalizedProductKey" VARCHAR(200) NOT NULL,
  "softwareVersion" TEXT,
  "status" TEXT NOT NULL DEFAULT 'OPEN',
  "category" TEXT NOT NULL,
  "priority" TEXT NOT NULL,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "title" VARCHAR(220) NOT NULL,
  "rationale" JSONB NOT NULL,
  "actions" JSONB NOT NULL,
  "advisoryIds" JSONB NOT NULL DEFAULT '[]',
  "openedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "lastDecisionAt" TIMESTAMP(3),
  "lastDecisionReason" TEXT,
  "lastDecisionUserId" TEXT,
  CONSTRAINT "AssetAdviceCase_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetAdviceCase_status_check" CHECK ("status" IN
    ('OPEN','IN_REVIEW','DISMISSED','WORK_COMPLETED')),
  CONSTRAINT "AssetAdviceCase_revision_check" CHECK ("revision" >= 1),
  CONSTRAINT "AssetAdviceCase_evidenceDigest_check" CHECK (length("evidenceFingerprint") = 64)
);
CREATE UNIQUE INDEX "AssetAdviceCase_org_inspection_asset_product"
 ON "AssetAdviceCase"("organizationId","inspectionId","externalId","normalizedProductKey");
CREATE INDEX "AssetAdviceCase_organizationId_status_updatedAt_idx"
 ON "AssetAdviceCase"("organizationId","status","updatedAt");
CREATE INDEX "AssetAdviceCase_organizationId_importId_idx"
 ON "AssetAdviceCase"("organizationId","importId");
CREATE INDEX "AssetAdviceCase_organizationId_inspectionId_idx"
 ON "AssetAdviceCase"("organizationId","inspectionId");
ALTER TABLE "AssetAdviceCase" ADD CONSTRAINT "AssetAdviceCase_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
 ON DELETE CASCADE ON UPDATE CASCADE;
CREATE TABLE "AssetAdviceCaseStep" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "caseId" TEXT NOT NULL,
  "actionCode" VARCHAR(80) NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'TODO',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "note" TEXT,
  "completedAt" TIMESTAMP(3),
  "completedByUserId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AssetAdviceCaseStep_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetAdviceCaseStep_status_check"
    CHECK ("status" IN ('TODO','IN_PROGRESS','BLOCKED','DONE')),
  CONSTRAINT "AssetAdviceCaseStep_revision_check" CHECK ("revision" >= 1)
);
CREATE UNIQUE INDEX "AssetAdviceCaseStep_caseId_actionCode_key"
 ON "AssetAdviceCaseStep"("caseId","actionCode");
CREATE INDEX "AssetAdviceCaseStep_organizationId_status_idx"
 ON "AssetAdviceCaseStep"("organizationId","status");
ALTER TABLE "AssetAdviceCaseStep" ADD CONSTRAINT "AssetAdviceCaseStep_caseId_fkey"
 FOREIGN KEY ("caseId") REFERENCES "AssetAdviceCase"("id")
 ON DELETE CASCADE ON UPDATE CASCADE;
