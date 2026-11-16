CREATE TABLE "BaselineReview" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "draftId" TEXT NOT NULL,
  "sourceRevision" INTEGER NOT NULL,
  "reportDigest" VARCHAR(64) NOT NULL,
  "questionnaireVersion" INTEGER NOT NULL DEFAULT 1,
  "revision" INTEGER NOT NULL DEFAULT 1,
  "state" VARCHAR(24) NOT NULL DEFAULT 'OPEN',
  "scope" VARCHAR(24) NOT NULL DEFAULT 'DEVELOPMENT_REVIEW',
  "issueCount" INTEGER NOT NULL DEFAULT 0,
  "blockingIssueCount" INTEGER NOT NULL DEFAULT 0,
  "reviewNotes" JSONB NOT NULL,
  "reviewerUserId" TEXT,
  "completedAt" TIMESTAMP(3),
  "createdById" TEXT NOT NULL,
  "updatedById" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "BaselineReview_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "BaselineReview_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineReview_revision_check"
    CHECK ("sourceRevision" >= 1 AND "revision" >= 1),
  CONSTRAINT "BaselineReview_scope_check"
    CHECK ("scope" = 'DEVELOPMENT_REVIEW'),
  CONSTRAINT "BaselineReview_state_check"
    CHECK ("state" IN ('OPEN','IN_REVIEW','CHANGES_REQUESTED',
      'TECHNICALLY_REVIEWED','REOPENED')),
  CONSTRAINT "BaselineReview_issue_count_check"
    CHECK ("issueCount" >= 0 AND "blockingIssueCount" >= 0 AND
      "blockingIssueCount" <= "issueCount"),
  CONSTRAINT "BaselineReview_digest_check"
    CHECK ("reportDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "BaselineReview_organizationId_draftId_sourceRevision_key"
  ON "BaselineReview"("organizationId","draftId","sourceRevision");
CREATE INDEX "BaselineReview_organizationId_state_updatedAt_idx"
  ON "BaselineReview"("organizationId","state","updatedAt");
CREATE INDEX "BaselineReview_organizationId_reviewerUserId_idx"
  ON "BaselineReview"("organizationId","reviewerUserId");

CREATE TABLE "BaselineReviewEvent" (
  "id" TEXT NOT NULL,
  "organizationId" TEXT NOT NULL,
  "reviewId" TEXT NOT NULL,
  "revision" INTEGER NOT NULL,
  "action" VARCHAR(30) NOT NULL,
  "previousState" VARCHAR(24) NOT NULL,
  "newState" VARCHAR(24) NOT NULL,
  "findingsDigest" VARCHAR(64) NOT NULL,
  "metadata" JSONB NOT NULL,
  "actorUserId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "BaselineReviewEvent_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "BaselineReviewEvent_organization_fkey"
    FOREIGN KEY ("organizationId") REFERENCES "Organization"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineReviewEvent_review_fkey"
    FOREIGN KEY ("reviewId") REFERENCES "BaselineReview"("id")
    ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "BaselineReviewEvent_revision_check"
    CHECK ("revision" >= 1),
  CONSTRAINT "BaselineReviewEvent_digest_check"
    CHECK ("findingsDigest" ~ '^[0-9a-f]{64}$')
);
CREATE UNIQUE INDEX "BaselineReviewEvent_reviewId_revision_key"
  ON "BaselineReviewEvent"("reviewId","revision");
CREATE INDEX "BaselineReviewEvent_organizationId_createdAt_idx"
  ON "BaselineReviewEvent"("organizationId","createdAt");
