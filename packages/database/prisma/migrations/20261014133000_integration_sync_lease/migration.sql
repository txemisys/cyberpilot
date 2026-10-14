-- CreateTable
CREATE TABLE "IntegrationSyncLease" (
    "integrationId" TEXT NOT NULL,
    "leaseToken" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IntegrationSyncLease_pkey" PRIMARY KEY ("integrationId")
);

-- CreateIndex
CREATE UNIQUE INDEX "IntegrationSyncLease_leaseToken_key" ON "IntegrationSyncLease"("leaseToken");

-- CreateIndex
CREATE INDEX "IntegrationSyncLease_expiresAt_idx" ON "IntegrationSyncLease"("expiresAt");

-- AddForeignKey
ALTER TABLE "IntegrationSyncLease"
ADD CONSTRAINT "IntegrationSyncLease_integrationId_fkey"
FOREIGN KEY ("integrationId") REFERENCES "Integration"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
