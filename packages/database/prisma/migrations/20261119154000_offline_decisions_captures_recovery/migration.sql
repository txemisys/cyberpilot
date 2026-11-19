CREATE TABLE "EvidenceDecisionCase" (
"id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,
"decisionKey" VARCHAR(64) NOT NULL,"sourceReportDigest" VARCHAR(64) NOT NULL,
"code" VARCHAR(48) NOT NULL,"priority" VARCHAR(8) NOT NULL,
"domain" VARCHAR(120) NOT NULL,"controlId" VARCHAR(160) NOT NULL,
"scope" VARCHAR(250) NOT NULL,"evidenceIds" JSONB NOT NULL,
"findingIds" JSONB NOT NULL,"relatedActionId" TEXT,
"ownerUserId" TEXT,"status" VARCHAR(20) NOT NULL DEFAULT 'OPEN',
"reviewNote" TEXT,"dueAt" TIMESTAMP(3),
"revision" INTEGER NOT NULL DEFAULT 1,
"createdById" TEXT NOT NULL,"updatedById" TEXT NOT NULL,
"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
"updatedAt" TIMESTAMP(3) NOT NULL,
CONSTRAINT "EvidenceDecisionCase_pkey" PRIMARY KEY ("id"),
CONSTRAINT "EvidenceDecisionCase_org_fk"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
 ON DELETE CASCADE ON UPDATE CASCADE,
CONSTRAINT "EvidenceDecisionCase_status_check" CHECK ("status" IN
 ('OPEN','IN_REVIEW','WAITING_EVIDENCE','REVIEW_REPORTED','REOPENED')),
CONSTRAINT "EvidenceDecisionCase_revision_check" CHECK ("revision">=1),
CONSTRAINT "EvidenceDecisionCase_key_check" CHECK ("decisionKey" ~ '^[a-f0-9]{64}$')
);
CREATE UNIQUE INDEX "EvidenceDecisionCase_organizationId_decisionKey_key"
 ON "EvidenceDecisionCase"("organizationId","decisionKey");
CREATE INDEX "EvidenceDecisionCase_organizationId_status_dueAt_idx"
 ON "EvidenceDecisionCase"("organizationId","status","dueAt");
CREATE INDEX "EvidenceDecisionCase_organizationId_ownerUserId_status_idx"
 ON "EvidenceDecisionCase"("organizationId","ownerUserId","status");
CREATE TABLE "EvidenceDecisionCaseEvent" (
"id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,
"caseId" TEXT NOT NULL,"revision" INTEGER NOT NULL,
"kind" VARCHAR(32) NOT NULL,"previousStatus" VARCHAR(20) NOT NULL,
"nextStatus" VARCHAR(20) NOT NULL,"actorUserId" TEXT NOT NULL,
"snapshotDigest" VARCHAR(64) NOT NULL,
"occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
CONSTRAINT "EvidenceDecisionCaseEvent_pkey" PRIMARY KEY ("id"),
CONSTRAINT "EvidenceDecisionCaseEvent_org_fk"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
 ON DELETE CASCADE ON UPDATE CASCADE,
CONSTRAINT "EvidenceDecisionCaseEvent_case_fk"
 FOREIGN KEY ("caseId") REFERENCES "EvidenceDecisionCase"("id")
 ON DELETE CASCADE ON UPDATE CASCADE,
CONSTRAINT "EvidenceDecisionCaseEvent_revision_check" CHECK ("revision">=1)
);
CREATE UNIQUE INDEX "EvidenceDecisionCaseEvent_caseId_revision_key"
 ON "EvidenceDecisionCaseEvent"("caseId","revision");
CREATE INDEX "EvidenceDecisionCaseEvent_organizationId_caseId_occurredAt_idx"
 ON "EvidenceDecisionCaseEvent"("organizationId","caseId","occurredAt");
CREATE TABLE "OfflineReportCapture" (
"id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,
"kind" VARCHAR(32) NOT NULL,"schemaVersion" VARCHAR(80) NOT NULL,
"originalDigest" VARCHAR(64) NOT NULL,"payloadDigest" VARCHAR(64) NOT NULL,
"payload" JSONB NOT NULL,"sourceComplete" BOOLEAN NOT NULL,
"createdById" TEXT NOT NULL,
"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
CONSTRAINT "OfflineReportCapture_pkey" PRIMARY KEY ("id"),
CONSTRAINT "OfflineReportCapture_org_fk"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
 ON DELETE CASCADE ON UPDATE CASCADE,
CONSTRAINT "OfflineReportCapture_digest_check"
 CHECK ("payloadDigest" ~ '^[a-f0-9]{64}$')
);
CREATE UNIQUE INDEX "OfflineReportCapture_organizationId_kind_payloadDigest_key"
 ON "OfflineReportCapture"("organizationId","kind","payloadDigest");
CREATE INDEX "OfflineReportCapture_organizationId_kind_createdAt_idx"
 ON "OfflineReportCapture"("organizationId","kind","createdAt");
CREATE TABLE "OfflineRecoveryRehearsal" (
"id" TEXT NOT NULL,"organizationId" TEXT NOT NULL,
"captureIds" JSONB NOT NULL,"manifest" JSONB NOT NULL,
"manifestDigest" VARCHAR(64) NOT NULL,
"status" VARCHAR(24) NOT NULL,"failures" JSONB NOT NULL,
"createdById" TEXT NOT NULL,
"createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
CONSTRAINT "OfflineRecoveryRehearsal_pkey" PRIMARY KEY ("id"),
CONSTRAINT "OfflineRecoveryRehearsal_org_fk"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
 ON DELETE CASCADE ON UPDATE CASCADE,
CONSTRAINT "OfflineRecoveryRehearsal_status_check"
 CHECK ("status" IN ('PASS','BLOCKED','INCOMPLETE'))
);
CREATE INDEX "OfflineRecoveryRehearsal_organizationId_createdAt_idx"
 ON "OfflineRecoveryRehearsal"("organizationId","createdAt");
