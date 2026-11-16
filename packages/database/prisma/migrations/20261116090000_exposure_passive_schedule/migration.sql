CREATE TABLE "ExposurePassiveSchedule" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "authorizationId" TEXT NOT NULL,
  "domain" VARCHAR(253) NOT NULL,
  "state" VARCHAR(24) NOT NULL DEFAULT 'DISABLED',
  "revision" INTEGER NOT NULL DEFAULT 1,
  "sources" JSONB NOT NULL,
  "policyDigest" VARCHAR(64) NOT NULL,
  "legalConsentVerified" BOOLEAN NOT NULL DEFAULT false,
  "minimumIntervalMs" INTEGER NOT NULL DEFAULT 60000,
  "nextEligibleAt" TIMESTAMP(3),
  "lastAttemptAt" TIMESTAMP(3),
  "dailyDnsLimit" INTEGER NOT NULL DEFAULT 8,
  "dailyTlsLimit" INTEGER NOT NULL DEFAULT 1,
  "dailyHttpLimit" INTEGER NOT NULL DEFAULT 1,
  "createdById" TEXT NOT NULL,
  "updatedById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ExposurePassiveSchedule_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExposurePassiveSchedule_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposurePassiveSchedule_state_check"
    CHECK ("state" IN ('DISABLED','PAUSED','READY','REVOKED')),
  CONSTRAINT "ExposurePassiveSchedule_revision_check"
    CHECK ("revision" >= 1),
  CONSTRAINT "ExposurePassiveSchedule_consent_check"
    CHECK ("state" NOT IN ('READY') OR "legalConsentVerified" = true),
  CONSTRAINT "ExposurePassiveSchedule_policy_digest_check"
    CHECK ("policyDigest" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "ExposurePassiveSchedule_rate_check"
    CHECK ("minimumIntervalMs" >= 60000),
  CONSTRAINT "ExposurePassiveSchedule_quota_check"
    CHECK ("dailyDnsLimit" BETWEEN 0 AND 8
      AND "dailyTlsLimit" BETWEEN 0 AND 1
      AND "dailyHttpLimit" BETWEEN 0 AND 1)
);
CREATE UNIQUE INDEX "ExposurePassiveSchedule_organizationId_domain_key"
  ON "ExposurePassiveSchedule"("organizationId","domain");
CREATE INDEX "ExposurePassiveSchedule_organizationId_state_nextEligibleAt_idx"
  ON "ExposurePassiveSchedule"("organizationId","state","nextEligibleAt");
CREATE INDEX "ExposurePassiveSchedule_organizationId_authorizationId_idx"
  ON "ExposurePassiveSchedule"("organizationId","authorizationId");

CREATE TABLE "ExposurePassiveReservation" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "scheduleId" TEXT NOT NULL,
  "requestId" VARCHAR(128) NOT NULL,
  "authorizationRevision" INTEGER NOT NULL,
  "status" VARCHAR(24) NOT NULL DEFAULT 'DENIED',
  "requestedSources" JSONB NOT NULL,
  "reservedDns" INTEGER NOT NULL DEFAULT 0,
  "reservedTls" INTEGER NOT NULL DEFAULT 0,
  "reservedHttp" INTEGER NOT NULL DEFAULT 0,
  "actualDns" INTEGER NOT NULL DEFAULT 0,
  "actualTls" INTEGER NOT NULL DEFAULT 0,
  "actualHttp" INTEGER NOT NULL DEFAULT 0,
  "periodStart" TIMESTAMP(3) NOT NULL,
  "leaseExpiresAt" TIMESTAMP(3) NOT NULL,
  "finishedAt" TIMESTAMP(3),
  "rejectionCode" VARCHAR(80),
  "evidenceDigest" VARCHAR(64),
  "initiatedById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ExposurePassiveReservation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExposurePassiveReservation_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposurePassiveReservation_schedule_fkey"
    FOREIGN KEY ("scheduleId") REFERENCES "ExposurePassiveSchedule"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposurePassiveReservation_status_check"
    CHECK ("status" IN ('DENIED','RESERVED','COMPLETED','FAILED','CANCELLED')),
  CONSTRAINT "ExposurePassiveReservation_counter_check"
    CHECK ("reservedDns" BETWEEN 0 AND 8 AND
      "reservedTls" BETWEEN 0 AND 1 AND
      "reservedHttp" BETWEEN 0 AND 1 AND
      "actualDns" BETWEEN 0 AND "reservedDns" AND
      "actualTls" BETWEEN 0 AND "reservedTls" AND
      "actualHttp" BETWEEN 0 AND "reservedHttp"),
  CONSTRAINT "ExposurePassiveReservation_evidence_digest_check"
    CHECK ("evidenceDigest" IS NULL OR
      "evidenceDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "ExposurePassiveReservation_organizationId_requestId_key"
  ON "ExposurePassiveReservation"("organizationId","requestId");
CREATE INDEX "ExposurePassiveReservation_organizationId_periodStart_status_idx"
  ON "ExposurePassiveReservation"("organizationId","periodStart","status");
CREATE INDEX "ExposurePassiveReservation_scheduleId_leaseExpiresAt_idx"
  ON "ExposurePassiveReservation"("scheduleId","leaseExpiresAt");

CREATE TABLE "ExposurePassiveEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "scheduleId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "action" VARCHAR(32) NOT NULL,
  "priorState" VARCHAR(24) NOT NULL,
  "currentState" VARCHAR(24) NOT NULL,
  "metadata" JSONB NOT NULL,
  "actorUserId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ExposurePassiveEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "ExposurePassiveEvent_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposurePassiveEvent_schedule_fkey"
    FOREIGN KEY ("scheduleId") REFERENCES "ExposurePassiveSchedule"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ExposurePassiveEvent_revision_check"
    CHECK ("revision" >= 1)
);
CREATE UNIQUE INDEX "ExposurePassiveEvent_scheduleId_revision_key"
  ON "ExposurePassiveEvent"("scheduleId","revision");
CREATE INDEX "ExposurePassiveEvent_organizationId_createdAt_idx"
  ON "ExposurePassiveEvent"("organizationId","createdAt");
