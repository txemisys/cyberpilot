CREATE TABLE "DurableOfflineJob" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "type" VARCHAR(48) NOT NULL,
 "status" VARCHAR(24) NOT NULL,
 "idempotencyKey" VARCHAR(128) NOT NULL,
 "requestDigest" VARCHAR(64) NOT NULL,
 "revision" INTEGER NOT NULL DEFAULT 1,
 "attempts" INTEGER NOT NULL DEFAULT 0,
 "maxAttempts" INTEGER NOT NULL,
 "scheduledAt" TIMESTAMP(3) NOT NULL,
 "expiresAt" TIMESTAMP(3) NOT NULL,
 "leaseExpiresAt" TIMESTAMP(3),
 "leaseToken" TEXT,
 "leasedBy" TEXT,
 "resultDigest" TEXT,
 "lastFailure" TEXT,
 "failureClass" TEXT,
 "snapshot" JSONB NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "DurableOfflineJob_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "DurableOfflineJobEvent" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "jobId" TEXT NOT NULL,
 "revision" INTEGER NOT NULL,
 "kind" VARCHAR(32) NOT NULL,
 "actorId" TEXT NOT NULL,
 "previousState" VARCHAR(24) NOT NULL,
 "nextState" VARCHAR(24) NOT NULL,
 "occurredAt" TIMESTAMP(3) NOT NULL,
 "snapshotDigest" VARCHAR(64) NOT NULL,
 "attempts" INTEGER NOT NULL,
 CONSTRAINT "DurableOfflineJobEvent_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "DurableOfflineJob_organizationId_idempotencyKey_key"
 ON "DurableOfflineJob"("organizationId", "idempotencyKey");
CREATE INDEX "DurableOfflineJob_organizationId_status_scheduledAt_idx"
 ON "DurableOfflineJob"("organizationId", "status", "scheduledAt");
CREATE INDEX "DurableOfflineJob_status_leaseExpiresAt_idx"
 ON "DurableOfflineJob"("status", "leaseExpiresAt");
CREATE INDEX "DurableOfflineJob_organizationId_type_createdAt_idx"
 ON "DurableOfflineJob"("organizationId", "type", "createdAt");
CREATE UNIQUE INDEX "DurableOfflineJobEvent_jobId_revision_key"
 ON "DurableOfflineJobEvent"("jobId", "revision");
CREATE INDEX "DurableOfflineJobEvent_organizationId_jobId_revision_idx"
 ON "DurableOfflineJobEvent"("organizationId", "jobId", "revision");
ALTER TABLE "DurableOfflineJob" ADD CONSTRAINT "DurableOfflineJob_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DurableOfflineJobEvent" ADD CONSTRAINT "DurableOfflineJobEvent_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DurableOfflineJobEvent" ADD CONSTRAINT "DurableOfflineJobEvent_jobId_fkey"
 FOREIGN KEY ("jobId") REFERENCES "DurableOfflineJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;
