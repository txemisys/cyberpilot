-- Provider-neutral observations live under organizations rather than an M365 integration.
CREATE TABLE "SecurityEvidence" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "schemaVersion" INTEGER NOT NULL DEFAULT 1,
    "source" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "controlId" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "observedAt" TIMESTAMP(3),
    "details" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SecurityEvidence_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "SecurityEvidence_organizationId_source_domain_controlId_scope_key"
  ON "SecurityEvidence"("organizationId", "source", "domain", "controlId", "scope");
CREATE INDEX "SecurityEvidence_organizationId_domain_state_idx"
  ON "SecurityEvidence"("organizationId", "domain", "state");
ALTER TABLE "SecurityEvidence"
  ADD CONSTRAINT "SecurityEvidence_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
