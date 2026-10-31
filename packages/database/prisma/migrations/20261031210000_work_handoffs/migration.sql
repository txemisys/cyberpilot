CREATE TYPE "WorkHandoffStatus" AS ENUM ('REQUESTED','ACCEPTED','DECLINED','CANCELLED');
CREATE TABLE "WorkHandoff" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "workItemId" TEXT NOT NULL,
 "requesterUserId" TEXT,
 "recipientUserId" TEXT NOT NULL,
 "decidedByUserId" TEXT,
 "status" "WorkHandoffStatus" NOT NULL DEFAULT 'REQUESTED',
 "reason" TEXT NOT NULL,
 "response" TEXT,
 "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "decidedAt" TIMESTAMP(3),
 "expiresAt" TIMESTAMP(3),
 "revision" INTEGER NOT NULL DEFAULT 1,
 CONSTRAINT "WorkHandoff_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "WorkHandoff_organizationId_workItemId_requestedAt_idx" ON "WorkHandoff"("organizationId","workItemId","requestedAt");
CREATE INDEX "WorkHandoff_organizationId_recipientUserId_status_idx" ON "WorkHandoff"("organizationId","recipientUserId","status");
CREATE INDEX "WorkHandoff_organizationId_status_expiresAt_idx" ON "WorkHandoff"("organizationId","status","expiresAt");
ALTER TABLE "WorkHandoff" ADD CONSTRAINT "WorkHandoff_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkHandoff" ADD CONSTRAINT "WorkHandoff_workItemId_fkey" FOREIGN KEY ("workItemId") REFERENCES "RemediationWorkItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkHandoff" ADD CONSTRAINT "WorkHandoff_requesterUserId_fkey" FOREIGN KEY ("requesterUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "WorkHandoff" ADD CONSTRAINT "WorkHandoff_recipientUserId_fkey" FOREIGN KEY ("recipientUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "WorkHandoff" ADD CONSTRAINT "WorkHandoff_decidedByUserId_fkey" FOREIGN KEY ("decidedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
