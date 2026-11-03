CREATE TABLE "IntegrityReviewWorkLink" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "taskId" TEXT NOT NULL,
  "workItemId" TEXT NOT NULL,
  "rationale" TEXT NOT NULL,
  "linkedByUserId" TEXT,
  "linkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "unlinkedAt" TIMESTAMP(3),
  "unlinkedByUserId" TEXT,
  "unlinkReason" TEXT,
  "revision" INTEGER NOT NULL DEFAULT 1,
  CONSTRAINT "IntegrityReviewWorkLink_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IntegrityReviewWorkLink_organizationId_taskId_workItemId_key"
  ON "IntegrityReviewWorkLink"("organizationId","taskId","workItemId");
CREATE INDEX "IntegrityReviewWorkLink_organizationId_taskId_unlinkedAt_idx"
  ON "IntegrityReviewWorkLink"("organizationId","taskId","unlinkedAt");
CREATE INDEX "IntegrityReviewWorkLink_organizationId_workItemId_unlinkedAt_idx"
  ON "IntegrityReviewWorkLink"("organizationId","workItemId","unlinkedAt");
ALTER TABLE "IntegrityReviewWorkLink" ADD CONSTRAINT "IntegrityReviewWorkLink_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityReviewWorkLink" ADD CONSTRAINT "IntegrityReviewWorkLink_taskId_fkey"
  FOREIGN KEY ("taskId") REFERENCES "IntegrityReviewTask"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityReviewWorkLink" ADD CONSTRAINT "IntegrityReviewWorkLink_workItemId_fkey"
  FOREIGN KEY ("workItemId") REFERENCES "RemediationWorkItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;
