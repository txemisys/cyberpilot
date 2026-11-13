CREATE TABLE "BaselineFollowUp" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "questionnaireVersion" INTEGER NOT NULL DEFAULT 1,
  "questionId" VARCHAR(80) NOT NULL,
  "sourceDraftRevision" INTEGER NOT NULL,
  "severity" VARCHAR(20) NOT NULL,
  "status" VARCHAR(24) NOT NULL DEFAULT 'OPEN',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "title" VARCHAR(512) NOT NULL,
  "nextAction" VARCHAR(2048) NOT NULL,
  "evidenceNeeded" VARCHAR(512) NOT NULL,
  "evidenceReference" VARCHAR(96),
  "ownerUserId" TEXT,
  "dueAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  "createdById" TEXT NOT NULL,
  "updatedById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "BaselineFollowUp_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "BaselineFollowUp_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineFollowUp_revision_check"
    CHECK ("revision" >= 1 AND "sourceDraftRevision" >= 1),
  CONSTRAINT "BaselineFollowUp_status_check"
    CHECK ("status" IN ('OPEN','IN_PROGRESS','BLOCKED',
      'COMPLETED_REPORTED','REOPENED')),
  CONSTRAINT "BaselineFollowUp_severity_check"
    CHECK ("severity" IN ('CRITICAL','HIGH','MEDIUM',
      'LOW','UNKNOWN','NOT_APPLICABLE')),
  CONSTRAINT "BaselineFollowUp_questionnaire_check"
    CHECK ("questionnaireVersion" = 1)
);
CREATE UNIQUE INDEX "BaselineFollowUp_organizationId_questionnaireVersion_questionId_key"
  ON "BaselineFollowUp"("organizationId","questionnaireVersion","questionId");
CREATE INDEX "BaselineFollowUp_organizationId_status_dueAt_idx"
  ON "BaselineFollowUp"("organizationId","status","dueAt");
CREATE INDEX "BaselineFollowUp_organizationId_ownerUserId_updatedAt_idx"
  ON "BaselineFollowUp"("organizationId","ownerUserId","updatedAt");
CREATE TABLE "BaselineFollowUpEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "followUpId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "action" VARCHAR(24) NOT NULL,
  "previousStatus" VARCHAR(24) NOT NULL,
  "nextStatus" VARCHAR(24) NOT NULL,
  "ownerUserId" TEXT,
  "dueAt" TIMESTAMP(3),
  "evidenceReference" VARCHAR(96),
  "actorUserId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "BaselineFollowUpEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "BaselineFollowUpEvent_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineFollowUpEvent_followUp_fkey"
    FOREIGN KEY ("followUpId") REFERENCES "BaselineFollowUp"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineFollowUpEvent_revision_check"
    CHECK ("revision" >= 1)
);
CREATE UNIQUE INDEX "BaselineFollowUpEvent_followUpId_revision_key"
  ON "BaselineFollowUpEvent"("followUpId","revision");
CREATE INDEX "BaselineFollowUpEvent_organizationId_createdAt_idx"
  ON "BaselineFollowUpEvent"("organizationId","createdAt");
