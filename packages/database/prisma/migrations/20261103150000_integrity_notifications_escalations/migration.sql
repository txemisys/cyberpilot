CREATE TYPE "IntegrityNotificationKind" AS ENUM ('REVIEW_ASSIGNED', 'REVIEW_OVERDUE', 'REVIEW_ESCALATED', 'REVIEW_RESOLVED', 'PROVIDER_FAILURE', 'PROVIDER_RECOVERED');
CREATE TYPE "IntegrityEscalationState" AS ENUM ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'CANCELLED');

CREATE TABLE "IntegrityNotification" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "taskId" TEXT NOT NULL,
  "recipientUserId" TEXT NOT NULL,
  "kind" "IntegrityNotificationKind" NOT NULL,
  "dedupeKey" TEXT NOT NULL,
  "title" TEXT NOT NULL,
  "message" TEXT NOT NULL,
  "context" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "readAt" TIMESTAMP(3),
  "dismissedAt" TIMESTAMP(3),
  "revision" INTEGER NOT NULL DEFAULT 1,
  CONSTRAINT "IntegrityNotification_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IntegrityNotification_organizationId_recipientUserId_dedupeKey_key"
  ON "IntegrityNotification"("organizationId", "recipientUserId", "dedupeKey");
CREATE INDEX "IntegrityNotification_organizationId_recipientUserId_createdAt_idx"
  ON "IntegrityNotification"("organizationId", "recipientUserId", "createdAt");
CREATE INDEX "IntegrityNotification_organizationId_taskId_createdAt_idx"
  ON "IntegrityNotification"("organizationId", "taskId", "createdAt");
CREATE INDEX "IntegrityNotification_organizationId_recipientUserId_readAt_idx"
  ON "IntegrityNotification"("organizationId", "recipientUserId", "readAt");
ALTER TABLE "IntegrityNotification" ADD CONSTRAINT "IntegrityNotification_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityNotification" ADD CONSTRAINT "IntegrityNotification_taskId_fkey"
  FOREIGN KEY ("taskId") REFERENCES "IntegrityReviewTask"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "IntegrityEscalation" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "taskId" TEXT NOT NULL,
  "level" INTEGER NOT NULL DEFAULT 1,
  "state" "IntegrityEscalationState" NOT NULL DEFAULT 'OPEN',
  "reason" TEXT NOT NULL,
  "dedupeKey" TEXT NOT NULL,
  "dueAt" TIMESTAMP(3) NOT NULL,
  "openedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "acknowledgedAt" TIMESTAMP(3),
  "resolvedAt" TIMESTAMP(3),
  "actorUserId" TEXT,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "IntegrityEscalation_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IntegrityEscalation_organizationId_taskId_dedupeKey_key"
  ON "IntegrityEscalation"("organizationId", "taskId", "dedupeKey");
CREATE INDEX "IntegrityEscalation_organizationId_state_dueAt_idx"
  ON "IntegrityEscalation"("organizationId", "state", "dueAt");
CREATE INDEX "IntegrityEscalation_organizationId_taskId_openedAt_idx"
  ON "IntegrityEscalation"("organizationId", "taskId", "openedAt");
ALTER TABLE "IntegrityEscalation" ADD CONSTRAINT "IntegrityEscalation_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityEscalation" ADD CONSTRAINT "IntegrityEscalation_taskId_fkey"
  FOREIGN KEY ("taskId") REFERENCES "IntegrityReviewTask"("id") ON DELETE CASCADE ON UPDATE CASCADE;
