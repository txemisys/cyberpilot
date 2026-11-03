CREATE TABLE "IntegrityProviderCheck" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "taskId" TEXT NOT NULL,
  "evidenceId" TEXT NOT NULL,
  "provider" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "controlId" TEXT NOT NULL,
  "outcome" TEXT NOT NULL,
  "providerObservedAt" TIMESTAMP(3),
  "checkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "requestedByUserId" TEXT,
  "requestKey" TEXT NOT NULL,
  "requestDigest" VARCHAR(64) NOT NULL,
  "observationDigest" VARCHAR(64) NOT NULL,
  "responseDigest" VARCHAR(64) NOT NULL,
  "responseMetadata" JSONB NOT NULL,
  "failureCode" TEXT,
  "failureMessage" TEXT,
  CONSTRAINT "IntegrityProviderCheck_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IntegrityProviderCheck_organizationId_requestedByUserId_requestKey_key"
  ON "IntegrityProviderCheck"("organizationId","requestedByUserId","requestKey");
CREATE INDEX "IntegrityProviderCheck_organizationId_taskId_checkedAt_idx"
  ON "IntegrityProviderCheck"("organizationId","taskId","checkedAt");
CREATE INDEX "IntegrityProviderCheck_organizationId_evidenceId_checkedAt_idx"
  ON "IntegrityProviderCheck"("organizationId","evidenceId","checkedAt");
CREATE INDEX "IntegrityProviderCheck_organizationId_provider_checkedAt_idx"
  ON "IntegrityProviderCheck"("organizationId","provider","checkedAt");
ALTER TABLE "IntegrityProviderCheck" ADD CONSTRAINT "IntegrityProviderCheck_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityProviderCheck" ADD CONSTRAINT "IntegrityProviderCheck_taskId_fkey"
  FOREIGN KEY ("taskId") REFERENCES "IntegrityReviewTask"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityProviderCheck" ADD CONSTRAINT "IntegrityProviderCheck_evidenceId_fkey"
  FOREIGN KEY ("evidenceId") REFERENCES "SecurityEvidence"("id") ON DELETE CASCADE ON UPDATE CASCADE;
