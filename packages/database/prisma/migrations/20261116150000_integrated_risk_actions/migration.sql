-- Independent cross-source SME risk follow-ups, deliberately separate
-- from connector remediations and historical CyberScore.
CREATE TABLE "IntegratedRiskAction" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "riskKey" VARCHAR(64) NOT NULL,
 "title" VARCHAR(250) NOT NULL,
 "description" TEXT NOT NULL DEFAULT '',
 "severity" VARCHAR(16) NOT NULL,
 "sourceFingerprint" VARCHAR(64) NOT NULL,
 "evidenceRefs" JSONB NOT NULL,
 "status" VARCHAR(24) NOT NULL DEFAULT 'OPEN',
 "priority" VARCHAR(12) NOT NULL DEFAULT 'NORMAL',
 "ownerUserId" TEXT,
 "dueAt" TIMESTAMP(3),
 "rationale" TEXT,
 "exceptionReason" TEXT,
 "exceptionExpiresAt" TIMESTAMP(3),
 "revision" INTEGER NOT NULL DEFAULT 1,
 "createdById" TEXT NOT NULL,
 "updatedById" TEXT NOT NULL,
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "IntegratedRiskAction_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "IntegratedRiskAction_organizationId_fkey"
   FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
   ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT "IntegratedRiskAction_risk_key_check"
   CHECK ("riskKey" ~ '^[a-f0-9]{64}$'),
 CONSTRAINT "IntegratedRiskAction_revision_check"
   CHECK ("revision" >= 1),
 CONSTRAINT "IntegratedRiskAction_status_check" CHECK ("status" IN
   ('OPEN','IN_PROGRESS','BLOCKED','DONE_REPORTED','EXCEPTION','REOPENED')),
 CONSTRAINT "IntegratedRiskAction_priority_check" CHECK ("priority" IN
   ('LOW','NORMAL','HIGH','URGENT'))
);
CREATE TABLE "IntegratedRiskActionEvent" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "actionId" TEXT NOT NULL,
 "revision" INTEGER NOT NULL,
 "kind" VARCHAR(24) NOT NULL,
 "previousStatus" VARCHAR(24) NOT NULL,
 "nextStatus" VARCHAR(24) NOT NULL,
 "actorUserId" TEXT NOT NULL,
 "snapshot" JSONB NOT NULL,
 "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CONSTRAINT "IntegratedRiskActionEvent_pkey" PRIMARY KEY ("id"),
 CONSTRAINT "IntegratedRiskActionEvent_organizationId_fkey"
   FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
   ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT "IntegratedRiskActionEvent_actionId_fkey"
   FOREIGN KEY ("actionId") REFERENCES "IntegratedRiskAction"("id")
   ON DELETE CASCADE ON UPDATE CASCADE,
 CONSTRAINT "IntegratedRiskActionEvent_revision_check"
   CHECK ("revision" >= 1)
);
CREATE UNIQUE INDEX "IntegratedRiskAction_organizationId_riskKey_key"
 ON "IntegratedRiskAction"("organizationId","riskKey");
CREATE INDEX "IntegratedRiskAction_organizationId_status_dueAt_idx"
 ON "IntegratedRiskAction"("organizationId","status","dueAt");
CREATE INDEX "IntegratedRiskAction_organizationId_ownerUserId_status_idx"
 ON "IntegratedRiskAction"("organizationId","ownerUserId","status");
CREATE UNIQUE INDEX "IntegratedRiskActionEvent_actionId_revision_key"
 ON "IntegratedRiskActionEvent"("actionId","revision");
CREATE INDEX "IntegratedRiskActionEvent_organizationId_actionId_occurredAt_idx"
 ON "IntegratedRiskActionEvent"("organizationId","actionId","occurredAt");
