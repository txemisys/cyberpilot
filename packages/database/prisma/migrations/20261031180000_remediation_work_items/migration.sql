-- Work tracking is independent of remediation verification and finding resolution.
CREATE TYPE "WorkItemStatus" AS ENUM ('TODO','IN_PROGRESS','BLOCKED','DONE','CANCELLED');
CREATE TYPE "WorkItemPriority" AS ENUM ('LOW','NORMAL','HIGH','URGENT');
CREATE TYPE "WorkItemEventKind" AS ENUM ('CREATED','UPDATED','COMMENTED','REOPENED');
CREATE TABLE "RemediationWorkItem" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "remediationId" TEXT NOT NULL,
 "findingId" TEXT NOT NULL,
 "title" TEXT NOT NULL,
 "description" TEXT NOT NULL DEFAULT '',
 "status" "WorkItemStatus" NOT NULL DEFAULT 'TODO',
 "priority" "WorkItemPriority" NOT NULL DEFAULT 'NORMAL',
 "assigneeUserId" TEXT,
 "dueAt" TIMESTAMP(3),
 "completedAt" TIMESTAMP(3),
 "revision" INTEGER NOT NULL DEFAULT 1,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "RemediationWorkItem_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "RemediationWorkEvent" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "workItemId" TEXT NOT NULL,
 "actorUserId" TEXT,
 "kind" "WorkItemEventKind" NOT NULL,
 "before" JSONB,
 "after" JSONB,
 "comment" TEXT,
 "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "RemediationWorkEvent_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "RemediationWorkItem_organizationId_remediationId_key"
 ON "RemediationWorkItem"("organizationId","remediationId");
CREATE INDEX "RemediationWorkItem_organizationId_status_dueAt_idx"
 ON "RemediationWorkItem"("organizationId","status","dueAt");
CREATE INDEX "RemediationWorkItem_organizationId_assigneeUserId_status_idx"
 ON "RemediationWorkItem"("organizationId","assigneeUserId","status");
CREATE INDEX "RemediationWorkItem_organizationId_priority_createdAt_idx"
 ON "RemediationWorkItem"("organizationId","priority","createdAt");
CREATE INDEX "RemediationWorkEvent_organizationId_workItemId_occurredAt_idx"
 ON "RemediationWorkEvent"("organizationId","workItemId","occurredAt");
CREATE INDEX "RemediationWorkEvent_organizationId_actorUserId_occurredAt_idx"
 ON "RemediationWorkEvent"("organizationId","actorUserId","occurredAt");
ALTER TABLE "RemediationWorkItem" ADD CONSTRAINT "RemediationWorkItem_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RemediationWorkItem" ADD CONSTRAINT "RemediationWorkItem_remediationId_fkey"
 FOREIGN KEY ("remediationId") REFERENCES "Remediation"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RemediationWorkItem" ADD CONSTRAINT "RemediationWorkItem_findingId_fkey"
 FOREIGN KEY ("findingId") REFERENCES "SecurityFinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RemediationWorkItem" ADD CONSTRAINT "RemediationWorkItem_assigneeUserId_fkey"
 FOREIGN KEY ("assigneeUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "RemediationWorkEvent" ADD CONSTRAINT "RemediationWorkEvent_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RemediationWorkEvent" ADD CONSTRAINT "RemediationWorkEvent_workItemId_fkey"
 FOREIGN KEY ("workItemId") REFERENCES "RemediationWorkItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "RemediationWorkEvent" ADD CONSTRAINT "RemediationWorkEvent_actorUserId_fkey"
 FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
