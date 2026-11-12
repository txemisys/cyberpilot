-- Opt-in multi-source CyberScore v2. Does not touch SecurityScore v1.
CREATE TABLE "MultiSourceV2Assessment" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "snapshotId" TEXT NOT NULL,
  "modelId" VARCHAR(80) NOT NULL,
  "modelRevision" INTEGER NOT NULL DEFAULT 1,
  "evaluatedAt" TIMESTAMP(3) NOT NULL,
  "score" INTEGER,
  "status" VARCHAR(48) NOT NULL,
  "coveragePercent" INTEGER NOT NULL,
  "riskPoints" DOUBLE PRECISION NOT NULL,
  "verifiedControls" INTEGER NOT NULL,
  "totalControls" INTEGER NOT NULL,
  "manifestDigest" VARCHAR(64) NOT NULL,
  "coverageDigest" VARCHAR(64) NOT NULL,
  "scoreDigest" VARCHAR(64) NOT NULL,
  "reportDigest" VARCHAR(64) NOT NULL,
  "manifest" JSONB NOT NULL,
  "coverage" JSONB NOT NULL,
  "scoreDetails" JSONB NOT NULL,
  "report" JSONB NOT NULL,
  "sourceClass" VARCHAR(32) NOT NULL,
  "createdById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "MultiSourceV2Assessment_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "MultiSourceV2Assessment_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "MultiSourceV2Assessment_model"
    CHECK ("modelId" = 'cyberpilot.multisource.v2' AND "modelRevision" = 1),
  CONSTRAINT "MultiSourceV2Assessment_score"
    CHECK ("score" IS NULL OR ("score" >= 0 AND "score" <= 100)),
  CONSTRAINT "MultiSourceV2Assessment_coverage"
    CHECK ("coveragePercent" >= 0 AND "coveragePercent" <= 100),
  CONSTRAINT "MultiSourceV2Assessment_risk"
    CHECK ("riskPoints" >= 0 AND "riskPoints" <= 100),
  CONSTRAINT "MultiSourceV2Assessment_control_counts"
    CHECK ("verifiedControls" >= 0 AND "totalControls" >= 0
      AND "verifiedControls" <= "totalControls"),
  CONSTRAINT "MultiSourceV2Assessment_status"
    CHECK ("status" IN ('ASSESSED_WITH_LIMITATIONS',
      'INSUFFICIENT_COVERAGE','UNASSESSABLE','INVALID_EVIDENCE')),
  CONSTRAINT "MultiSourceV2Assessment_source_class"
    CHECK ("sourceClass" IN ('SYNTHETIC_FIXTURE','AUTHORIZED_EVIDENCE')),
  CONSTRAINT "MultiSourceV2Assessment_manifest_hash"
    CHECK ("manifestDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "MultiSourceV2Assessment_coverage_hash"
    CHECK ("coverageDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "MultiSourceV2Assessment_score_hash"
    CHECK ("scoreDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "MultiSourceV2Assessment_report_hash"
    CHECK ("reportDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "MultiSourceV2Assessment_organizationId_snapshotId_key"
  ON "MultiSourceV2Assessment"("organizationId", "snapshotId");
CREATE INDEX "MultiSourceV2Assessment_organizationId_evaluatedAt_idx"
  ON "MultiSourceV2Assessment"("organizationId", "evaluatedAt");
CREATE INDEX "MultiSourceV2Assessment_organizationId_status_evaluatedAt_idx"
  ON "MultiSourceV2Assessment"("organizationId", "status", "evaluatedAt");
CREATE INDEX "MultiSourceV2Assessment_organizationId_modelId_modelRevision_idx"
  ON "MultiSourceV2Assessment"("organizationId", "modelId", "modelRevision");
