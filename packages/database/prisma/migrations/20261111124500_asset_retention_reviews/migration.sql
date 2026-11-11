-- Human administrative retention review; a recorded exception is not deletion or legal approval.
CREATE TABLE "AssetRetentionReview" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "importId" TEXT NOT NULL,
  "state" TEXT NOT NULL DEFAULT 'PENDING',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "sourceDigest" VARCHAR(64) NOT NULL,
  "privacyDigest" VARCHAR(64) NOT NULL,
  "policyDigest" VARCHAR(64) NOT NULL,
  "assessmentAt" TIMESTAMP(3) NOT NULL,
  "snapshot" JSONB NOT NULL,
  "requestedByUserId" TEXT NOT NULL,
  "initialReason" TEXT NOT NULL,
  "reviewedByUserId" TEXT,
  "decisionReason" TEXT,
  "acknowledgements" JSONB NOT NULL,
  "exceptions" JSONB NOT NULL,
  "backupDisposition" TEXT NOT NULL DEFAULT 'UNVERIFIED',
  "personalDataDisposition" TEXT NOT NULL DEFAULT 'REQUIRES_REVIEW',
  "nextReviewAt" TIMESTAMP(3),
  "decidedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AssetRetentionReview_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetRetentionReview_revision_check" CHECK ("revision" >= 1),
  CONSTRAINT "AssetRetentionReview_state_check" CHECK
    ("state" IN ('PENDING','IN_REVIEW','DOCUMENTED_WITH_EXCEPTIONS','REJECTED','REOPENED')),
  CONSTRAINT "AssetRetentionReview_backup_check" CHECK
    ("backupDisposition" IN ('UNVERIFIED','PROCEDURE_DOCUMENTED','REQUIRES_EXTERNAL_VERIFICATION')),
  CONSTRAINT "AssetRetentionReview_pii_check" CHECK
    ("personalDataDisposition" IN ('REQUIRES_REVIEW','RETENTION_DOCUMENTED','EXTERNAL_APPROVAL_REQUIRED'))
);
CREATE UNIQUE INDEX "AssetRetentionReview_organizationId_importId_key"
  ON "AssetRetentionReview" ("organizationId","importId");
CREATE INDEX "AssetRetentionReview_organizationId_state_updatedAt_idx"
  ON "AssetRetentionReview" ("organizationId","state","updatedAt");
CREATE INDEX "AssetRetentionReview_organizationId_nextReviewAt_idx"
  ON "AssetRetentionReview" ("organizationId","nextReviewAt");
ALTER TABLE "AssetRetentionReview"
  ADD CONSTRAINT "AssetRetentionReview_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
