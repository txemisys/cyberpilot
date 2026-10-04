-- CyberPilot baseline generated from the current Prisma schema.
-- This migration represents the complete schema as of 2026-10-04.

CREATE TYPE "MembershipRole" AS ENUM ('OWNER', 'ADMIN', 'MEMBER', 'AUDITOR');
CREATE TYPE "AuditActorType" AS ENUM ('USER', 'SYSTEM', 'INTEGRATION');
CREATE TYPE "IntegrationProvider" AS ENUM ('MICROSOFT_365');
CREATE TYPE "IntegrationStatus" AS ENUM ('PENDING', 'CONNECTED', 'ERROR', 'DISCONNECTED');
CREATE TYPE "IntegrationMode" AS ENUM ('LIVE', 'LAB');
CREATE TYPE "IntegrationCapabilityStatus" AS ENUM ('UNKNOWN', 'AVAILABLE', 'PERMISSION_REQUIRED', 'ERROR');
CREATE TYPE "IntegrationConsentPurpose" AS ENUM ('SCANNER', 'REMEDIATION');
CREATE TYPE "DirectoryIdentityType" AS ENUM ('MEMBER', 'GUEST', 'UNKNOWN');
CREATE TYPE "FindingSeverity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE "FindingStatus" AS ENUM ('OPEN', 'RESOLVED');
CREATE TYPE "DomainSpfStatus" AS ENUM ('UNKNOWN', 'MISSING', 'PRESENT', 'MULTIPLE', 'ERROR');
CREATE TYPE "DomainDmarcStatus" AS ENUM ('UNKNOWN', 'MISSING', 'MONITORING', 'ENFORCING', 'INVALID', 'ERROR');
CREATE TYPE "DomainDkimStatus" AS ENUM ('UNKNOWN', 'MISSING', 'PARTIAL', 'PUBLISHED', 'ERROR');
CREATE TYPE "ScoreCoverage" AS ENUM ('COMPLETE', 'PARTIAL');
CREATE TYPE "RemediationMode" AS ENUM ('GUIDED', 'AUTOMATED');
CREATE TYPE "RemediationStatus" AS ENUM ('PROPOSED', 'APPROVED', 'EXECUTING', 'SUCCEEDED', 'FAILED', 'CANCELLED', 'VERIFIED');

CREATE TABLE "User" (
  "id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "emailVerified" BOOLEAN NOT NULL DEFAULT false,
  "image" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Session" (
  "id" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "token" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "ipAddress" TEXT,
  "userAgent" TEXT,
  "userId" TEXT NOT NULL,
  CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Account" (
  "id" TEXT NOT NULL,
  "accountId" TEXT NOT NULL,
  "providerId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "accessToken" TEXT,
  "refreshToken" TEXT,
  "idToken" TEXT,
  "accessTokenExpiresAt" TIMESTAMP(3),
  "refreshTokenExpiresAt" TIMESTAMP(3),
  "scope" TEXT,
  "password" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Account_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Verification" (
  "id" TEXT NOT NULL,
  "identifier" TEXT NOT NULL,
  "value" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Verification_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Organization" (
  "id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "slug" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Membership" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "role" "MembershipRole" NOT NULL DEFAULT 'MEMBER',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Membership_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Integration" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "provider" "IntegrationProvider" NOT NULL,
  "status" "IntegrationStatus" NOT NULL DEFAULT 'PENDING',
  "mode" "IntegrationMode" NOT NULL DEFAULT 'LIVE',
  "externalTenantId" TEXT,
  "displayName" TEXT,
  "connectedAt" TIMESTAMP(3),
  "lastSyncAt" TIMESTAMP(3),
  "lastErrorAt" TIMESTAMP(3),
  "lastErrorCode" TEXT,
  "mfaEvidenceStatus" "IntegrationCapabilityStatus" NOT NULL DEFAULT 'UNKNOWN',
  "mfaEvidenceCheckedAt" TIMESTAMP(3),
  "remediationStatus" "IntegrationCapabilityStatus" NOT NULL DEFAULT 'UNKNOWN',
  "remediationCheckedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Integration_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DirectoryIdentity" (
  "id" TEXT NOT NULL,
  "integrationId" TEXT NOT NULL,
  "externalId" TEXT NOT NULL,
  "displayName" TEXT,
  "userPrincipalName" TEXT,
  "accountEnabled" BOOLEAN,
  "identityType" "DirectoryIdentityType" NOT NULL DEFAULT 'UNKNOWN',
  "createdAtProvider" TIMESTAMP(3),
  "isAdmin" BOOLEAN,
  "isMfaRegistered" BOOLEAN,
  "isMfaCapable" BOOLEAN,
  "isPasswordlessCapable" BOOLEAN,
  "methodsRegistered" JSONB,
  "authenticationObservedAt" TIMESTAMP(3),
  "authenticationUpdatedAt" TIMESTAMP(3),
  "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "DirectoryIdentity_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DirectoryRoleDefinition" (
  "id" TEXT NOT NULL,
  "integrationId" TEXT NOT NULL,
  "externalId" TEXT NOT NULL,
  "templateId" TEXT,
  "displayName" TEXT NOT NULL,
  "isBuiltIn" BOOLEAN,
  "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "DirectoryRoleDefinition_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DirectoryRoleAssignment" (
  "id" TEXT NOT NULL,
  "integrationId" TEXT NOT NULL,
  "externalId" TEXT NOT NULL,
  "principalExternalId" TEXT NOT NULL,
  "roleDefinitionExternalId" TEXT NOT NULL,
  "directoryScopeId" TEXT,
  "observedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "DirectoryRoleAssignment_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Domain" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "integrationId" TEXT,
  "name" TEXT NOT NULL,
  "isDefault" BOOLEAN NOT NULL DEFAULT false,
  "isInitial" BOOLEAN NOT NULL DEFAULT false,
  "spfStatus" "DomainSpfStatus" NOT NULL DEFAULT 'UNKNOWN',
  "spfRecords" JSONB,
  "dmarcStatus" "DomainDmarcStatus" NOT NULL DEFAULT 'UNKNOWN',
  "dmarcPolicy" TEXT,
  "dmarcRecords" JSONB,
  "dkimStatus" "DomainDkimStatus" NOT NULL DEFAULT 'UNKNOWN',
  "dkimSelectors" JSONB,
  "dnsObservedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Domain_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SecurityFinding" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "integrationId" TEXT,
  "key" TEXT NOT NULL,
  "ruleId" TEXT NOT NULL,
  "title" TEXT NOT NULL,
  "description" TEXT NOT NULL,
  "severity" "FindingSeverity" NOT NULL,
  "status" "FindingStatus" NOT NULL DEFAULT 'OPEN',
  "evidence" JSONB,
  "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "resolvedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "SecurityFinding_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Remediation" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "findingId" TEXT NOT NULL,
  "playbookId" TEXT NOT NULL,
  "mode" "RemediationMode" NOT NULL,
  "status" "RemediationStatus" NOT NULL DEFAULT 'PROPOSED',
  "title" TEXT NOT NULL,
  "summary" TEXT NOT NULL,
  "steps" JSONB NOT NULL,
  "verification" JSONB NOT NULL,
  "actionType" TEXT,
  "actionPayload" JSONB,
  "executionEvidence" JSONB,
  "failureCode" TEXT,
  "approvedByUserId" TEXT,
  "approvedAt" TIMESTAMP(3),
  "startedAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  "verifiedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "Remediation_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SecurityScore" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "modelVersion" TEXT NOT NULL,
  "score" INTEGER NOT NULL,
  "riskPoints" DOUBLE PRECISION NOT NULL,
  "coverage" "ScoreCoverage" NOT NULL,
  "supportedFindingCount" INTEGER NOT NULL,
  "unsupportedFindingCount" INTEGER NOT NULL,
  "details" JSONB,
  "calculatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "SecurityScore_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "IntegrationConsentState" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "provider" "IntegrationProvider" NOT NULL,
  "purpose" "IntegrationConsentPurpose" NOT NULL DEFAULT 'SCANNER',
  "nonceHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "IntegrationConsentState_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "AuditEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "actorType" "AuditActorType" NOT NULL,
  "actorUserId" TEXT,
  "action" TEXT NOT NULL,
  "resourceType" TEXT NOT NULL,
  "resourceId" TEXT,
  "metadata" JSONB,
  "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "Session_token_key" ON "Session"("token");
CREATE INDEX "Session_userId_idx" ON "Session"("userId");
CREATE INDEX "Account_userId_idx" ON "Account"("userId");
CREATE UNIQUE INDEX "Account_providerId_accountId_key" ON "Account"("providerId", "accountId");
CREATE INDEX "Verification_identifier_idx" ON "Verification"("identifier");
CREATE UNIQUE INDEX "Organization_slug_key" ON "Organization"("slug");
CREATE UNIQUE INDEX "Membership_organizationId_userId_key" ON "Membership"("organizationId", "userId");
CREATE INDEX "Membership_userId_idx" ON "Membership"("userId");
CREATE UNIQUE INDEX "Integration_organizationId_provider_key" ON "Integration"("organizationId", "provider");
CREATE UNIQUE INDEX "Integration_provider_externalTenantId_key" ON "Integration"("provider", "externalTenantId");
CREATE INDEX "Integration_organizationId_idx" ON "Integration"("organizationId");
CREATE UNIQUE INDEX "DirectoryIdentity_integrationId_externalId_key" ON "DirectoryIdentity"("integrationId", "externalId");
CREATE INDEX "DirectoryIdentity_integrationId_accountEnabled_idx" ON "DirectoryIdentity"("integrationId", "accountEnabled");
CREATE UNIQUE INDEX "DirectoryRoleDefinition_integrationId_externalId_key" ON "DirectoryRoleDefinition"("integrationId", "externalId");
CREATE INDEX "DirectoryRoleDefinition_integrationId_idx" ON "DirectoryRoleDefinition"("integrationId");
CREATE UNIQUE INDEX "DirectoryRoleAssignment_integrationId_externalId_key" ON "DirectoryRoleAssignment"("integrationId", "externalId");
CREATE INDEX "DirectoryRoleAssignment_integrationId_principalExternalId_idx" ON "DirectoryRoleAssignment"("integrationId", "principalExternalId");
CREATE INDEX "DirectoryRoleAssignment_integrationId_roleDefinitionExternalId_idx" ON "DirectoryRoleAssignment"("integrationId", "roleDefinitionExternalId");
CREATE UNIQUE INDEX "Domain_organizationId_name_key" ON "Domain"("organizationId", "name");
CREATE INDEX "Domain_integrationId_idx" ON "Domain"("integrationId");
CREATE INDEX "Domain_organizationId_isInitial_idx" ON "Domain"("organizationId", "isInitial");
CREATE UNIQUE INDEX "SecurityFinding_organizationId_key_key" ON "SecurityFinding"("organizationId", "key");
CREATE INDEX "SecurityFinding_organizationId_status_severity_idx" ON "SecurityFinding"("organizationId", "status", "severity");
CREATE INDEX "SecurityFinding_integrationId_idx" ON "SecurityFinding"("integrationId");
CREATE INDEX "Remediation_organizationId_status_createdAt_idx" ON "Remediation"("organizationId", "status", "createdAt");
CREATE INDEX "Remediation_findingId_idx" ON "Remediation"("findingId");
CREATE INDEX "SecurityScore_organizationId_calculatedAt_idx" ON "SecurityScore"("organizationId", "calculatedAt");
CREATE UNIQUE INDEX "IntegrationConsentState_nonceHash_key" ON "IntegrationConsentState"("nonceHash");
CREATE INDEX "IntegrationConsentState_organizationId_provider_purpose_expiresAt_idx" ON "IntegrationConsentState"("organizationId", "provider", "purpose", "expiresAt");
CREATE INDEX "IntegrationConsentState_userId_expiresAt_idx" ON "IntegrationConsentState"("userId", "expiresAt");
CREATE INDEX "AuditEvent_organizationId_occurredAt_idx" ON "AuditEvent"("organizationId", "occurredAt");
CREATE INDEX "AuditEvent_actorUserId_idx" ON "AuditEvent"("actorUserId");

ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Account" ADD CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Integration" ADD CONSTRAINT "Integration_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DirectoryIdentity" ADD CONSTRAINT "DirectoryIdentity_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "Integration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DirectoryRoleDefinition" ADD CONSTRAINT "DirectoryRoleDefinition_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "Integration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DirectoryRoleAssignment" ADD CONSTRAINT "DirectoryRoleAssignment_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "Integration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "DirectoryRoleAssignment" ADD CONSTRAINT "DirectoryRoleAssignment_integrationId_roleDefinitionExternalId_fkey" FOREIGN KEY ("integrationId", "roleDefinitionExternalId") REFERENCES "DirectoryRoleDefinition"("integrationId", "externalId") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Domain" ADD CONSTRAINT "Domain_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Domain" ADD CONSTRAINT "Domain_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "Integration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SecurityFinding" ADD CONSTRAINT "SecurityFinding_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "SecurityFinding" ADD CONSTRAINT "SecurityFinding_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "Integration"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Remediation" ADD CONSTRAINT "Remediation_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Remediation" ADD CONSTRAINT "Remediation_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "SecurityFinding"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Remediation" ADD CONSTRAINT "Remediation_approvedByUserId_fkey" FOREIGN KEY ("approvedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "SecurityScore" ADD CONSTRAINT "SecurityScore_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrationConsentState" ADD CONSTRAINT "IntegrationConsentState_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrationConsentState" ADD CONSTRAINT "IntegrationConsentState_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
