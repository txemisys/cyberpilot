-- Human decisions about offline evidence; never a LIVE provider attestation.
CREATE TABLE "AssetReleaseReview" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "importId" TEXT NOT NULL,
    "inspectionId" TEXT NOT NULL,
    "inventoryDigest" VARCHAR(64) NOT NULL,
    "inspectionDigest" VARCHAR(64) NOT NULL,
    "acceptanceDigest" VARCHAR(64) NOT NULL,
    "privacyDigest" VARCHAR(64) NOT NULL,
    "scenarioDigest" VARCHAR(64) NOT NULL,
    "evidenceBundleDigest" VARCHAR(64) NOT NULL,
    "policyDigest" VARCHAR(64) NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'PENDING',
    "revision" INTEGER NOT NULL DEFAULT 1,
    "operatorUserId" TEXT NOT NULL,
    "operatorReason" TEXT NOT NULL,
    "operatorAcknowledgements" JSONB NOT NULL,
    "exclusions" JSONB NOT NULL,
    "acceptanceSnapshot" JSONB NOT NULL,
    "privacySnapshot" JSONB NOT NULL,
    "scenarioSummary" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "decidedAt" TIMESTAMP(3),
    "decidedByUserId" TEXT,
    "decisionReason" TEXT,
    CONSTRAINT "AssetReleaseReview_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "AssetReleaseReview_revision_check" CHECK ("revision" >= 1),
    CONSTRAINT "AssetReleaseReview_state_check" CHECK ("state" IN ('PENDING','IN_REVIEW','ACCEPTED_OFFLINE','REJECTED','REOPENED'))
);
CREATE UNIQUE INDEX "AssetReleaseReview_organizationId_importId_inspectionId_key"
    ON "AssetReleaseReview"("organizationId","importId","inspectionId");
CREATE INDEX "AssetReleaseReview_organizationId_state_updatedAt_idx"
    ON "AssetReleaseReview"("organizationId","state","updatedAt");
CREATE INDEX "AssetReleaseReview_organizationId_createdAt_idx"
    ON "AssetReleaseReview"("organizationId","createdAt");
ALTER TABLE "AssetReleaseReview"
    ADD CONSTRAINT "AssetReleaseReview_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
