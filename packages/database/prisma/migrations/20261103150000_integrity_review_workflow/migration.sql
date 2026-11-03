-- Persistent, tenant-scoped integrity review workflow.
CREATE TYPE "IntegrityReviewDisposition" AS ENUM ('OPEN','ACKNOWLEDGED','IN_REVIEW','RESOLVED','WAIVED','REOPENED');
CREATE TYPE "IntegrityReviewAction" AS ENUM ('ACKNOWLEDGE','START_REVIEW','RESOLVE','WAIVE','REOPEN');

CREATE TABLE "IntegrityReviewTask" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "captureId" TEXT NOT NULL,
  "externalTaskId" TEXT NOT NULL,
  "title" TEXT NOT NULL,
  "severity" TEXT NOT NULL,
  "required" BOOLEAN NOT NULL DEFAULT true,
  "disposition" "IntegrityReviewDisposition" NOT NULL DEFAULT 'OPEN',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "ownerUserId" TEXT,
  "resolutionReason" TEXT,
  "resolutionRefs" JSONB,
  "completedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "IntegrityReviewTask_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IntegrityReviewTask_organizationId_captureId_externalTaskId_key" ON "IntegrityReviewTask"("organizationId","captureId","externalTaskId");
CREATE INDEX "IntegrityReviewTask_organizationId_disposition_updatedAt_idx" ON "IntegrityReviewTask"("organizationId","disposition","updatedAt");
CREATE INDEX "IntegrityReviewTask_organizationId_captureId_createdAt_idx" ON "IntegrityReviewTask"("organizationId","captureId","createdAt");
ALTER TABLE "IntegrityReviewTask" ADD CONSTRAINT "IntegrityReviewTask_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityReviewTask" ADD CONSTRAINT "IntegrityReviewTask_captureId_fkey" FOREIGN KEY ("captureId") REFERENCES "IntegrityCaseCapture"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "IntegrityReviewEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "taskId" TEXT NOT NULL,
  "actorUserId" TEXT,
  "action" "IntegrityReviewAction" NOT NULL,
  "revisionBefore" INTEGER NOT NULL,
  "revisionAfter" INTEGER NOT NULL,
  "before" "IntegrityReviewDisposition" NOT NULL,
  "after" "IntegrityReviewDisposition" NOT NULL,
  "reason" TEXT,
  "evidenceRefs" JSONB,
  "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "IntegrityReviewEvent_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IntegrityReviewEvent_taskId_revisionAfter_key" ON "IntegrityReviewEvent"("taskId","revisionAfter");
CREATE INDEX "IntegrityReviewEvent_organizationId_taskId_occurredAt_idx" ON "IntegrityReviewEvent"("organizationId","taskId","occurredAt");
CREATE INDEX "IntegrityReviewEvent_organizationId_actorUserId_occurredAt_idx" ON "IntegrityReviewEvent"("organizationId","actorUserId","occurredAt");
ALTER TABLE "IntegrityReviewEvent" ADD CONSTRAINT "IntegrityReviewEvent_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityReviewEvent" ADD CONSTRAINT "IntegrityReviewEvent_taskId_fkey" FOREIGN KEY ("taskId") REFERENCES "IntegrityReviewTask"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityReviewEvent" ADD CONSTRAINT "IntegrityReviewEvent_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TABLE "IntegrityReviewCommand" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "taskId" TEXT NOT NULL,
  "actorUserId" TEXT NOT NULL,
  "idempotencyKey" TEXT NOT NULL,
  "payloadDigest" VARCHAR(64) NOT NULL,
  "response" JSONB NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "IntegrityReviewCommand_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IntegrityReviewCommand_organizationId_actorUserId_idempotencyKey_key" ON "IntegrityReviewCommand"("organizationId","actorUserId","idempotencyKey");
CREATE INDEX "IntegrityReviewCommand_organizationId_taskId_createdAt_idx" ON "IntegrityReviewCommand"("organizationId","taskId","createdAt");
ALTER TABLE "IntegrityReviewCommand" ADD CONSTRAINT "IntegrityReviewCommand_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityReviewCommand" ADD CONSTRAINT "IntegrityReviewCommand_taskId_fkey" FOREIGN KEY ("taskId") REFERENCES "IntegrityReviewTask"("id") ON DELETE CASCADE ON UPDATE CASCADE;
