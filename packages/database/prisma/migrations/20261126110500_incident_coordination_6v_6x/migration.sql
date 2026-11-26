CREATE TABLE "IncidentCoordinationRecord" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "incidentId" TEXT NOT NULL,
  "kind" VARCHAR(24) NOT NULL,
  "state" VARCHAR(32) NOT NULL,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "snapshot" JSONB NOT NULL,
  "snapshotDigest" VARCHAR(64) NOT NULL,
  "sourceDigest" VARCHAR(64) NOT NULL,
  "createdById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "IncidentCoordinationRecord_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "IncidentCoordinationRecord_organizationId_incidentId_kind_updatedAt_idx"
  ON "IncidentCoordinationRecord"("organizationId","incidentId","kind","updatedAt");
CREATE INDEX "IncidentCoordinationRecord_organizationId_kind_state_updatedAt_idx"
  ON "IncidentCoordinationRecord"("organizationId","kind","state","updatedAt");
ALTER TABLE "IncidentCoordinationRecord"
  ADD CONSTRAINT "IncidentCoordinationRecord_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentCoordinationRecord"
  ADD CONSTRAINT "IncidentCoordinationRecord_incidentId_fkey"
  FOREIGN KEY ("incidentId") REFERENCES "GuidedIncidentCase"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
CREATE TABLE "IncidentCoordinationEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "recordId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "commandId" VARCHAR(128) NOT NULL,
  "actorUserId" TEXT NOT NULL,
  "action" VARCHAR(48) NOT NULL,
  "occurredAt" TIMESTAMP(3) NOT NULL,
  "beforeDigest" VARCHAR(64),
  "afterDigest" VARCHAR(64) NOT NULL,
  "previousEventDigest" VARCHAR(64),
  "eventDigest" VARCHAR(64) NOT NULL,
  CONSTRAINT "IncidentCoordinationEvent_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "IncidentCoordinationEvent_recordId_revision_key"
  ON "IncidentCoordinationEvent"("recordId","revision");
CREATE UNIQUE INDEX "IncidentCoordinationEvent_recordId_commandId_key"
  ON "IncidentCoordinationEvent"("recordId","commandId");
CREATE INDEX "IncidentCoordinationEvent_organizationId_recordId_occurredAt_idx"
  ON "IncidentCoordinationEvent"("organizationId","recordId","occurredAt");
ALTER TABLE "IncidentCoordinationEvent"
  ADD CONSTRAINT "IncidentCoordinationEvent_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentCoordinationEvent"
  ADD CONSTRAINT "IncidentCoordinationEvent_recordId_fkey"
  FOREIGN KEY ("recordId") REFERENCES "IncidentCoordinationRecord"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
