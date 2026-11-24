CREATE TABLE "IncidentTabletopSession" (
  "id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,"incidentId" TEXT,
  "revision" INTEGER NOT NULL DEFAULT 1,"state" VARCHAR(24) NOT NULL,
  "snapshot" JSONB NOT NULL,"snapshotDigest" VARCHAR(64) NOT NULL,
  "createdById" TEXT NOT NULL,
  "updatedAt" TIMESTAMP(3) NOT NULL,"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "IncidentTabletopSession_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "IncidentTabletopSessionEvent" (
  "id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,"sessionId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,"commandId" TEXT NOT NULL,
  "actorUserId" TEXT NOT NULL,"kind" VARCHAR(32) NOT NULL,
  "at" TIMESTAMP(3) NOT NULL,"beforeDigest" VARCHAR(64),
  "afterDigest" VARCHAR(64) NOT NULL,"priorEventDigest" VARCHAR(64),
  "eventDigest" VARCHAR(64) NOT NULL,"moveAccepted" BOOLEAN,
  CONSTRAINT "IncidentTabletopSessionEvent_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "IncidentTabletopSession_organizationId_incidentId_updatedAt_idx"
  ON "IncidentTabletopSession"("organizationId","incidentId","updatedAt");
CREATE INDEX "IncidentTabletopSession_organizationId_state_createdAt_idx"
  ON "IncidentTabletopSession"("organizationId","state","createdAt");
CREATE UNIQUE INDEX "IncidentTabletopSessionEvent_sessionId_revision_key"
  ON "IncidentTabletopSessionEvent"("sessionId","revision");
CREATE UNIQUE INDEX "IncidentTabletopSessionEvent_sessionId_commandId_key"
  ON "IncidentTabletopSessionEvent"("sessionId","commandId");
CREATE INDEX "IncidentTabletopSessionEvent_organizationId_sessionId_at_idx"
  ON "IncidentTabletopSessionEvent"("organizationId","sessionId","at");
ALTER TABLE "IncidentTabletopSession" ADD CONSTRAINT "IncidentTabletopSession_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentTabletopSessionEvent" ADD CONSTRAINT "IncidentTabletopSessionEvent_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentTabletopSessionEvent" ADD CONSTRAINT "IncidentTabletopSessionEvent_sessionId_fkey"
  FOREIGN KEY ("sessionId") REFERENCES "IncidentTabletopSession"("id") ON DELETE CASCADE ON UPDATE CASCADE;
