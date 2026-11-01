CREATE TABLE "IntegrityCaseCapture" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL,
    "complete" BOOLEAN NOT NULL,
    "caseCount" INTEGER NOT NULL,
    "digest" VARCHAR(64) NOT NULL,
    "payload" JSONB NOT NULL,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "IntegrityCaseCapture_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "IntegrityCaseCapture_organizationId_source_capturedAt_key"
    ON "IntegrityCaseCapture"("organizationId", "source", "capturedAt");
CREATE INDEX "IntegrityCaseCapture_organizationId_capturedAt_idx"
    ON "IntegrityCaseCapture"("organizationId", "capturedAt");
CREATE INDEX "IntegrityCaseCapture_organizationId_source_capturedAt_idx"
    ON "IntegrityCaseCapture"("organizationId", "source", "capturedAt");

ALTER TABLE "IntegrityCaseCapture"
    ADD CONSTRAINT "IntegrityCaseCapture_organizationId_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IntegrityCaseCapture"
    ADD CONSTRAINT "IntegrityCaseCapture_createdById_fkey"
    FOREIGN KEY ("createdById") REFERENCES "User"("id")
    ON DELETE SET NULL ON UPDATE CASCADE;
