CREATE TABLE "IncidentSituationReview" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "incidentId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "state" VARCHAR(24) NOT NULL,
  "situationDigest" VARCHAR(64) NOT NULL,
  "snapshotDigest" VARCHAR(64) NOT NULL,
  "snapshot" JSONB NOT NULL,
  "createdById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "IncidentSituationReview_pkey" PRIMARY KEY ("id")
);
CREATE TABLE "IncidentSituationReviewEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "reviewId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "actorUserId" TEXT NOT NULL,
  "decision" VARCHAR(32) NOT NULL,
  "occurredAt" TIMESTAMP(3) NOT NULL,
  "eventDigest" VARCHAR(64) NOT NULL,
  "previousDigest" VARCHAR(64),
  "nextDigest" VARCHAR(64) NOT NULL,
  "previousState" VARCHAR(24),
  "nextState" VARCHAR(24) NOT NULL,
  CONSTRAINT "IncidentSituationReviewEvent_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "IncidentSituationReview_organizationId_incidentId_createdAt_idx"
  ON "IncidentSituationReview"("organizationId", "incidentId", "createdAt");
CREATE INDEX "IncidentSituationReview_organizationId_state_updatedAt_idx"
  ON "IncidentSituationReview"("organizationId", "state", "updatedAt");
CREATE UNIQUE INDEX "IncidentSituationReviewEvent_reviewId_revision_key"
  ON "IncidentSituationReviewEvent"("reviewId", "revision");
CREATE INDEX "IncidentSituationReviewEvent_organizationId_reviewId_occurredAt_idx"
  ON "IncidentSituationReviewEvent"("organizationId", "reviewId", "occurredAt");
ALTER TABLE "IncidentSituationReview" ADD CONSTRAINT "IncidentSituationReview_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentSituationReview" ADD CONSTRAINT "IncidentSituationReview_incidentId_fkey"
  FOREIGN KEY ("incidentId") REFERENCES "GuidedIncidentCase"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentSituationReviewEvent" ADD CONSTRAINT "IncidentSituationReviewEvent_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentSituationReviewEvent" ADD CONSTRAINT "IncidentSituationReviewEvent_reviewId_fkey"
  FOREIGN KEY ("reviewId") REFERENCES "IncidentSituationReview"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
