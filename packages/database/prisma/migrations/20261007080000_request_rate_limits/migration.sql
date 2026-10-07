CREATE TABLE "RequestRateLimit" (
  "id" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "subjectHash" TEXT NOT NULL,
  "windowStart" TIMESTAMP(3) NOT NULL,
  "count" INTEGER NOT NULL DEFAULT 1,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "RequestRateLimit_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "RequestRateLimit_scope_subjectHash_windowStart_key"
ON "RequestRateLimit"("scope", "subjectHash", "windowStart");

CREATE INDEX "RequestRateLimit_expiresAt_idx"
ON "RequestRateLimit"("expiresAt");
