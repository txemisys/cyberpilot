CREATE TABLE "IncidentAssuranceHandoffBoard" (
 "id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,
 "incidentId" TEXT NOT NULL,"revision" INTEGER NOT NULL DEFAULT 1,
 "state" VARCHAR(24) NOT NULL,"snapshot" JSONB NOT NULL,
 "snapshotDigest" VARCHAR(64) NOT NULL,"assuranceDigest" VARCHAR(64) NOT NULL,
 "createdById" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "IncidentAssuranceHandoffBoard_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "IncidentAssuranceHandoffEvent" (
 "id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,
 "boardId" TEXT NOT NULL,"revision" INTEGER NOT NULL,
 "commandId" TEXT NOT NULL,"actorUserId" TEXT NOT NULL,
 "action" VARCHAR(32) NOT NULL,"occurredAt" TIMESTAMP(3) NOT NULL,
 "eventDigest" VARCHAR(64) NOT NULL,"previousDigest" VARCHAR(64),
 "nextDigest" VARCHAR(64) NOT NULL,"priorEventDigest" VARCHAR(64),
 "handoffId" TEXT,
 CONSTRAINT "IncidentAssuranceHandoffEvent_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "IncidentAssuranceHandoffBoard_organizationId_incidentId_createdAt_idx"
 ON "IncidentAssuranceHandoffBoard"("organizationId","incidentId","createdAt");
CREATE INDEX "IncidentAssuranceHandoffBoard_organizationId_state_updatedAt_idx"
 ON "IncidentAssuranceHandoffBoard"("organizationId","state","updatedAt");
CREATE UNIQUE INDEX "IncidentAssuranceHandoffEvent_boardId_revision_key"
 ON "IncidentAssuranceHandoffEvent"("boardId","revision");
CREATE UNIQUE INDEX "IncidentAssuranceHandoffEvent_boardId_commandId_key"
 ON "IncidentAssuranceHandoffEvent"("boardId","commandId");
CREATE INDEX "IncidentAssuranceHandoffEvent_organizationId_boardId_occurredAt_idx"
 ON "IncidentAssuranceHandoffEvent"("organizationId","boardId","occurredAt");
ALTER TABLE "IncidentAssuranceHandoffBoard" ADD CONSTRAINT
 "IncidentAssuranceHandoffBoard_organizationId_fkey" FOREIGN KEY ("organizationId")
 REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentAssuranceHandoffEvent" ADD CONSTRAINT
 "IncidentAssuranceHandoffEvent_organizationId_fkey" FOREIGN KEY ("organizationId")
 REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentAssuranceHandoffEvent" ADD CONSTRAINT
 "IncidentAssuranceHandoffEvent_boardId_fkey" FOREIGN KEY ("boardId")
 REFERENCES "IncidentAssuranceHandoffBoard"("id") ON DELETE CASCADE ON UPDATE CASCADE;
