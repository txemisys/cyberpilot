CREATE TABLE "WorkChecklistEntry" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "workItemId" TEXT NOT NULL,
 "position" INTEGER NOT NULL,
 "title" TEXT NOT NULL,
 "description" TEXT NOT NULL DEFAULT '',
 "completedAt" TIMESTAMP(3),
 "completedByUserId" TEXT,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "WorkChecklistEntry_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "WorkChecklistEntry_workItemId_position_key" ON "WorkChecklistEntry"("workItemId","position");
CREATE INDEX "WorkChecklistEntry_organizationId_workItemId_completedAt_idx" ON "WorkChecklistEntry"("organizationId","workItemId","completedAt");
ALTER TABLE "WorkChecklistEntry" ADD CONSTRAINT "WorkChecklistEntry_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkChecklistEntry" ADD CONSTRAINT "WorkChecklistEntry_workItemId_fkey"
 FOREIGN KEY ("workItemId") REFERENCES "RemediationWorkItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkChecklistEntry" ADD CONSTRAINT "WorkChecklistEntry_completedByUserId_fkey"
 FOREIGN KEY ("completedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
