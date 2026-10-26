CREATE TABLE "GuidedRemediationStep" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "remediationId" TEXT NOT NULL,
  "stepIndex" INTEGER NOT NULL,
  "actorUserId" TEXT NOT NULL,
  "acknowledgedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "GuidedRemediationStep_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "GuidedRemediationStep_remediationId_stepIndex_key" ON "GuidedRemediationStep"("remediationId", "stepIndex");
CREATE INDEX "GuidedRemediationStep_organizationId_remediationId_idx" ON "GuidedRemediationStep"("organizationId", "remediationId");
ALTER TABLE "GuidedRemediationStep" ADD CONSTRAINT "GuidedRemediationStep_remediationId_fkey" FOREIGN KEY ("remediationId") REFERENCES "Remediation"("id") ON DELETE CASCADE ON UPDATE CASCADE;
