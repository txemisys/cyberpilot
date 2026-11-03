CREATE TYPE "IntegrityEvidenceDecision" AS ENUM ('ACCEPTED', 'REJECTED', 'INCONCLUSIVE');

CREATE TABLE "IntegrityEvidenceAssessment" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "taskId" TEXT NOT NULL,
    "evidenceId" TEXT NOT NULL,
    "assessorUserId" TEXT,
    "decision" "IntegrityEvidenceDecision" NOT NULL,
    "rationale" TEXT NOT NULL,
    "observationDigest" VARCHAR(64) NOT NULL,
    "observedAt" TIMESTAMP(3),
    "source" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "evidenceState" TEXT NOT NULL,
    "evidenceUpdatedAt" TIMESTAMP(3) NOT NULL,
    "revision" INTEGER NOT NULL,
    "idempotencyKey" TEXT NOT NULL,
    "requestDigest" VARCHAR(64) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "IntegrityEvidenceAssessment_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "IntegrityEvidenceAssessment_organizationId_assessorUserId_idempotencyKey_key"
ON "IntegrityEvidenceAssessment"("organizationId", "assessorUserId", "idempotencyKey");
CREATE UNIQUE INDEX "IntegrityEvidenceAssessment_taskId_revision_key"
ON "IntegrityEvidenceAssessment"("taskId", "revision");
CREATE INDEX "IntegrityEvidenceAssessment_organizationId_taskId_createdAt_idx"
ON "IntegrityEvidenceAssessment"("organizationId", "taskId", "createdAt");
CREATE INDEX "IntegrityEvidenceAssessment_organizationId_evidenceId_createdAt_idx"
ON "IntegrityEvidenceAssessment"("organizationId", "evidenceId", "createdAt");
ALTER TABLE "IntegrityEvidenceAssessment"
ADD CONSTRAINT "IntegrityEvidenceAssessment_organizationId_fkey"
FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityEvidenceAssessment"
ADD CONSTRAINT "IntegrityEvidenceAssessment_taskId_fkey"
FOREIGN KEY ("taskId") REFERENCES "IntegrityReviewTask"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityEvidenceAssessment"
ADD CONSTRAINT "IntegrityEvidenceAssessment_evidenceId_fkey"
FOREIGN KEY ("evidenceId") REFERENCES "SecurityEvidence"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityReviewTask" ADD COLUMN "assessmentRevision" INTEGER NOT NULL DEFAULT 0;
