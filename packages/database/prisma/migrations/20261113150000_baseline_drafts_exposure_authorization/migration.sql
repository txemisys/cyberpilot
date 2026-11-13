CREATE TABLE "BaselineDraft" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "questionnaireVersion" INTEGER NOT NULL DEFAULT 1,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "status" VARCHAR(20) NOT NULL DEFAULT 'DRAFT',
  "responses" JSONB NOT NULL,
  "responsesDigest" VARCHAR(64) NOT NULL,
  "createdById" TEXT NOT NULL,
  "updatedById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "submittedAt" TIMESTAMP(3),
  CONSTRAINT "BaselineDraft_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "BaselineDraft_organization_fkey" FOREIGN KEY ("organizationId")
    REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineDraft_revision_check" CHECK ("revision" >= 1),
  CONSTRAINT "BaselineDraft_status_check"
    CHECK ("status" IN ('DRAFT','SUBMITTED')),
  CONSTRAINT "BaselineDraft_questionnaire_version_check"
    CHECK ("questionnaireVersion" = 1),
  CONSTRAINT "BaselineDraft_digest_check"
    CHECK ("responsesDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "BaselineDraft_organizationId_questionnaireVersion_key"
  ON "BaselineDraft"("organizationId","questionnaireVersion");
CREATE INDEX "BaselineDraft_organizationId_status_updatedAt_idx"
  ON "BaselineDraft"("organizationId","status","updatedAt");
CREATE TABLE "BaselineRevision" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "draftId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "eventKind" VARCHAR(24) NOT NULL,
  "questionnaireVersion" INTEGER NOT NULL,
  "responses" JSONB NOT NULL,
  "responsesDigest" VARCHAR(64) NOT NULL,
  "assessmentDigest" VARCHAR(64),
  "reportDigest" VARCHAR(64),
  "assessment" JSONB,
  "report" JSONB,
  "actorUserId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "BaselineRevision_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "BaselineRevision_organization_fkey" FOREIGN KEY ("organizationId")
    REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineRevision_draft_fkey" FOREIGN KEY ("draftId")
    REFERENCES "BaselineDraft"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineRevision_kind_check"
    CHECK ("eventKind" IN ('SAVE','SUBMIT','REOPEN')),
  CONSTRAINT "BaselineRevision_counter_check"
    CHECK ("revision" >= 1),
  CONSTRAINT "BaselineRevision_digest_check"
    CHECK ("responsesDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "BaselineRevision_assessment_digest_check"
    CHECK ("assessmentDigest" IS NULL OR "assessmentDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "BaselineRevision_report_digest_check"
    CHECK ("reportDigest" IS NULL OR "reportDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "BaselineRevision_draftId_revision_key"
  ON "BaselineRevision"("draftId","revision");
CREATE INDEX "BaselineRevision_organizationId_createdAt_idx"
  ON "BaselineRevision"("organizationId","createdAt");
CREATE INDEX "BaselineRevision_organizationId_draftId_revision_idx"
  ON "BaselineRevision"("organizationId","draftId","revision");
CREATE TABLE "ExposureDomainAuthorization" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "domain" VARCHAR(253) NOT NULL,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "state" VARCHAR(24) NOT NULL DEFAULT 'PENDING',
  "method" VARCHAR(20) NOT NULL,
  "challengeDigest" VARCHAR(64) NOT NULL,
  "challengeExpiresAt" TIMESTAMP(3) NOT NULL,
  "verifiedAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "lastCheckedAt" TIMESTAMP(3),
  "evidenceDigest" VARCHAR(64),
  "actorUserId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ExposureDomainAuthorization_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExposureDomainAuthorization_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposureDomainAuthorization_revision_check"
    CHECK ("revision" >= 1),
  CONSTRAINT "ExposureDomainAuthorization_state_check"
    CHECK ("state" IN ('PENDING','VERIFIED','EXPIRED','REVOKED')),
  CONSTRAINT "ExposureDomainAuthorization_method_check"
    CHECK ("method" IN ('DNS_TOKEN','HTTP_TOKEN')),
  CONSTRAINT "ExposureDomainAuthorization_challenge_check"
    CHECK ("challengeDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "ExposureDomainAuthorization_evidence_check"
    CHECK ("evidenceDigest" IS NULL OR "evidenceDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "ExposureDomainAuthorization_organizationId_domain_key"
  ON "ExposureDomainAuthorization"("organizationId","domain");
CREATE INDEX "ExposureDomainAuthorization_organizationId_state_updatedAt_idx"
  ON "ExposureDomainAuthorization"("organizationId","state","updatedAt");
CREATE TABLE "ExposureAuthorizationEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "authorizationId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "action" VARCHAR(32) NOT NULL,
  "priorState" VARCHAR(24) NOT NULL,
  "newState" VARCHAR(24) NOT NULL,
  "evidenceDigest" VARCHAR(64),
  "actorUserId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ExposureAuthorizationEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExposureAuthorizationEvent_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposureAuthorizationEvent_authorization_fkey"
    FOREIGN KEY ("authorizationId") REFERENCES "ExposureDomainAuthorization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposureAuthorizationEvent_revision_check"
    CHECK ("revision" >= 1),
  CONSTRAINT "ExposureAuthorizationEvent_evidence_check"
    CHECK ("evidenceDigest" IS NULL OR "evidenceDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "ExposureAuthorizationEvent_authorizationId_revision_key"
  ON "ExposureAuthorizationEvent"("authorizationId","revision");
CREATE INDEX "ExposureAuthorizationEvent_organizationId_createdAt_idx"
  ON "ExposureAuthorizationEvent"("organizationId","createdAt");
