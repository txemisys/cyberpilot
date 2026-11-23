CREATE TABLE "GuidedIncidentCase" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "type" VARCHAR(48) NOT NULL,
    "status" VARCHAR(24) NOT NULL,
    "severity" VARCHAR(16) NOT NULL,
    "title" VARCHAR(180) NOT NULL,
    "subjectReference" VARCHAR(220) NOT NULL,
    "ownerUserId" TEXT,
    "relatedDecisionCaseId" TEXT,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "snapshotDigest" VARCHAR(64) NOT NULL,
    "snapshot" JSONB NOT NULL,
    "createdById" TEXT NOT NULL,
    "updatedById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "GuidedIncidentCase_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "GuidedIncidentEvent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "command" VARCHAR(32) NOT NULL,
    "actorUserId" TEXT NOT NULL,
    "previousState" VARCHAR(24) NOT NULL,
    "nextState" VARCHAR(24) NOT NULL,
    "occurredAt" TIMESTAMP(3) NOT NULL,
    "snapshotDigest" VARCHAR(64) NOT NULL,
    CONSTRAINT "GuidedIncidentEvent_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "GuidedIncidentCase_organizationId_status_updatedAt_idx" ON "GuidedIncidentCase"("organizationId", "status", "updatedAt");
CREATE INDEX "GuidedIncidentCase_organizationId_type_severity_idx" ON "GuidedIncidentCase"("organizationId", "type", "severity");
CREATE INDEX "GuidedIncidentCase_organizationId_ownerUserId_idx" ON "GuidedIncidentCase"("organizationId", "ownerUserId");
CREATE UNIQUE INDEX "GuidedIncidentEvent_incidentId_revision_key" ON "GuidedIncidentEvent"("incidentId", "revision");
CREATE INDEX "GuidedIncidentEvent_organizationId_incidentId_occurredAt_idx" ON "GuidedIncidentEvent"("organizationId", "incidentId", "occurredAt");
ALTER TABLE "GuidedIncidentCase" ADD CONSTRAINT "GuidedIncidentCase_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "GuidedIncidentEvent" ADD CONSTRAINT "GuidedIncidentEvent_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "GuidedIncidentEvent" ADD CONSTRAINT "GuidedIncidentEvent_incidentId_fkey"
 FOREIGN KEY ("incidentId") REFERENCES "GuidedIncidentCase"("id") ON DELETE CASCADE ON UPDATE CASCADE;
