CREATE TABLE "AssetOsvDispatchNonce" (
 "id" TEXT NOT NULL,
 "organizationId" TEXT NOT NULL,
 "nonceDigest" VARCHAR(64) NOT NULL,
 "requestDigest" VARCHAR(64) NOT NULL,
 "keyId" VARCHAR(100) NOT NULL,
 "scheduleId" TEXT NOT NULL,
 "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "expiresAt" TIMESTAMP(3) NOT NULL,
 CONSTRAINT "AssetOsvDispatchNonce_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "AssetOsvDispatchNonce_organizationId_nonceDigest_key"
 ON "AssetOsvDispatchNonce"("organizationId", "nonceDigest");
CREATE INDEX "AssetOsvDispatchNonce_organizationId_acceptedAt_idx"
 ON "AssetOsvDispatchNonce"("organizationId", "acceptedAt");
CREATE INDEX "AssetOsvDispatchNonce_organizationId_expiresAt_idx"
 ON "AssetOsvDispatchNonce"("organizationId", "expiresAt");
ALTER TABLE "AssetOsvDispatchNonce" ADD CONSTRAINT "AssetOsvDispatchNonce_organizationId_fkey"
 FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
 ON DELETE CASCADE ON UPDATE CASCADE;
