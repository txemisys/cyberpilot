-- Cross-checked operator references; matching reference does not authenticate an external issuer.
CREATE TABLE "AssetEvidenceReview" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "acceptanceRunId" TEXT NOT NULL,
  "stepCode" TEXT NOT NULL,
  "sourceRunRevision" INTEGER NOT NULL,
  "evidenceDigest" VARCHAR(64) NOT NULL,
  "reviewState" TEXT NOT NULL DEFAULT 'NOT_CHECKED',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "originalOperatorUserId" TEXT NOT NULL,
  "reviewerUserId" TEXT NOT NULL,
  "reviewerReason" TEXT NOT NULL,
  "referenceLocation" TEXT,
  "referenceObservedAt" TIMESTAMP(3),
  "crossCheckedIdentifiers" JSONB NOT NULL,
  "limitations" JSONB NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AssetEvidenceReview_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AssetEvidenceReview_revision_check" CHECK ("revision" >= 1),
  CONSTRAINT "AssetEvidenceReview_source_revision_check" CHECK ("sourceRunRevision" >= 1),
  CONSTRAINT "AssetEvidenceReview_state_check" CHECK
    ("reviewState" IN ('NOT_CHECKED', 'REFERENCE_MATCHED',
      'DISPUTED', 'STALE_REFERENCE'))
);
CREATE UNIQUE INDEX "AssetEvidenceReview_organizationId_acceptanceRunId_stepCode_key"
  ON "AssetEvidenceReview"("organizationId","acceptanceRunId","stepCode");
CREATE INDEX "AssetEvidenceReview_organizationId_reviewState_updatedAt_idx"
  ON "AssetEvidenceReview"("organizationId","reviewState","updatedAt");
CREATE INDEX "AssetEvidenceReview_organizationId_acceptanceRunId_idx"
  ON "AssetEvidenceReview"("organizationId","acceptanceRunId");
ALTER TABLE "AssetEvidenceReview" ADD CONSTRAINT "AssetEvidenceReview_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
