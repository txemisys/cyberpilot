CREATE TABLE "WorkEvidenceLink" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "workItemId" TEXT NOT NULL,
 "evidenceId" TEXT NOT NULL,
 "reason" TEXT NOT NULL,
 "linkedByUserId" TEXT,
 "linkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "unlinkedAt" TIMESTAMP(3),
 "unlinkedByUserId" TEXT,
 CONSTRAINT "WorkEvidenceLink_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WorkEvidenceLink_workItemId_evidenceId_key" ON "WorkEvidenceLink"("workItemId","evidenceId");
CREATE INDEX "WorkEvidenceLink_organizationId_workItemId_unlinkedAt_idx" ON "WorkEvidenceLink"("organizationId","workItemId","unlinkedAt");
CREATE INDEX "WorkEvidenceLink_organizationId_evidenceId_idx" ON "WorkEvidenceLink"("organizationId","evidenceId");
ALTER TABLE "WorkEvidenceLink" ADD CONSTRAINT "WorkEvidenceLink_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkEvidenceLink" ADD CONSTRAINT "WorkEvidenceLink_workItemId_fkey"
 FOREIGN KEY ("workItemId") REFERENCES "RemediationWorkItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkEvidenceLink" ADD CONSTRAINT "WorkEvidenceLink_evidenceId_fkey"
 FOREIGN KEY ("evidenceId") REFERENCES "SecurityEvidence"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkEvidenceLink" ADD CONSTRAINT "WorkEvidenceLink_linkedByUserId_fkey"
 FOREIGN KEY ("linkedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "WorkEvidenceLink" ADD CONSTRAINT "WorkEvidenceLink_unlinkedByUserId_fkey"
 FOREIGN KEY ("unlinkedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
