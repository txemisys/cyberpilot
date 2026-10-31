import { describe, expect, it } from "vitest";
import {
  buildFindingEvidenceReview,
  rankEvidenceReviews,
  summarizeEvidenceReviews,
  evidenceReviewCsv,
  type ReviewFinding,
  type ReviewAction,
} from "./finding-evidence-review";
import {
  classifyStoredEvidenceState,
  parseReviewListOptions,
  reviewListUrl,
} from "./finding-review-data";

const at = (day: string) => new Date(day + "T10:00:00.000Z");
const action = (
  status = "APPROVED",
  acknowledgedSteps: ReadonlySet<number> = new Set<number>(),
): ReviewAction => ({
  id: "action-1",
  title: "Enable MFA",
  status,
  mode: "GUIDED",
  createdAt: at("2026-01-01"),
  approvedAt: at("2026-01-02"),
  startedAt: null,
  completedAt: null,
  verifiedAt: null,
  steps: ["Configure policy", "Test administrator sign-in"],
  verification: ["Check fresh identity evidence"],
  acknowledgedSteps,
});
const finding = (overrides: Partial<ReviewFinding> = {}): ReviewFinding => ({
  id: "finding-1",
  title: "Administrator MFA disabled",
  description: "A privileged identity is missing MFA.",
  severity: "HIGH",
  status: "OPEN",
  firstSeenAt: at("2026-01-01"),
  lastSeenAt: at("2026-01-03"),
  resolvedAt: null,
  evidence: [],
  actions: [],
  ...overrides,
});

describe("Finding evidence review", () => {
  it("distinguishes unaddressed findings from observed security signals", () => {
    const review = buildFindingEvidenceReview(finding());
    expect(review.status).toBe("unaddressed");
    expect(review.observedCount).toBe(0);
    expect(review.verifiedActionCount).toBe(0);
    expect(review.mostRecentObservationAt).toBeNull();
  });
  it("does not treat guided acknowledgements as verification", () => {
    const review = buildFindingEvidenceReview(
      finding({ actions: [action("APPROVED", new Set([0, 1]))] }),
    );
    expect(review.status).toBe("ready-for-check");
    expect(review.requiresFreshEvidence).toBe(true);
    expect(review.acknowledgedStepCount).toBe(2);
    expect(review.verifiedActionCount).toBe(0);
  });
  it("does not treat succeeded automated execution as verification", () => {
    const result = buildFindingEvidenceReview(
      finding({
        actions: [{
          ...action("SUCCEEDED"),
          mode: "AUTOMATED",
          completedAt: at("2026-01-04"),
        }],
      }),
    );
    expect(result.status).toBe("ready-for-check");
    expect(result.verificationAt).toBeNull();
  });
  it("requires verified state and a timestamp for action verification", () => {
    const notVerified = buildFindingEvidenceReview(
      finding({ actions: [action("VERIFIED")] }),
    );
    expect(notVerified.verifiedActionCount).toBe(0);
    const verified = buildFindingEvidenceReview(finding({
      actions: [{
        ...action("VERIFIED"),
        verifiedAt: at("2026-01-05"),
      }],
    }));
    expect(verified.verifiedActionCount).toBe(1);
    expect(verified.verificationAt).toEqual(at("2026-01-05"));
  });
  it("keeps finding resolution distinct from action verification", () => {
    const resolved = buildFindingEvidenceReview(finding({
      status: "RESOLVED",
      resolvedAt: at("2026-01-05"),
    }));
    expect(resolved.status).toBe("finding-resolved");
    expect(resolved.verifiedActionCount).toBe(0);
  });
  it("tracks declared, observed, unknown and error signals independently", () => {
    const states = ["OBSERVED", "DECLARED", "UNKNOWN", "ERROR"] as const;
    const review = buildFindingEvidenceReview(finding({
      evidence: states.map((source, index) => ({
        id: String(index), source, category: "IDENTITY",
        capturedAt: at("2026-01-01"),
        lastObservedAt: source === "OBSERVED" ? at("2026-01-02") : null,
        summary: source,
      })),
    }));
    expect(review.observedCount).toBe(1);
    expect(review.declaredCount).toBe(1);
    expect(review.unknownCount).toBe(1);
    expect(review.errorCount).toBe(1);
    expect(review.mostRecentObservationAt).toEqual(at("2026-01-02"));
  });
  it("ranks review readiness and severity without mutating input", () => {
    const reviews = [
      buildFindingEvidenceReview(finding({ id: "unaddressed" })),
      buildFindingEvidenceReview(finding({
        id: "verification",
        actions: [action("SUCCEEDED")],
        severity: "MEDIUM",
      })),
    ];
    const original = reviews.map(item => item.findingId);
    expect(rankEvidenceReviews(reviews).map(item => item.findingId))
      .toEqual(["verification", "unaddressed"]);
    expect(reviews.map(item => item.findingId)).toEqual(original);
  });
  it("summarizes distinct provenance counts", () => {
    const review = buildFindingEvidenceReview(finding({
      actions: [action("APPROVED", new Set([0, 1]))],
    }));
    const summary = summarizeEvidenceReviews([review]);
    expect(summary.total).toBe(1);
    expect(summary.pendingEvidence).toBe(1);
    expect(summary.verified).toBe(0);
  });
  it("neutralizes spreadsheet formula injection in export fields", () => {
    const csv = evidenceReviewCsv([buildFindingEvidenceReview(
      finding({ title: '=HYPERLINK("bad")' }),
    )]);
    expect(csv).toContain("'=HYPERLINK");
    expect(csv).toContain('""bad""');
    expect(csv.startsWith("\uFEFF")).toBe(true);
  });
});

describe("Evidence review URL and source normalization", () => {
  it("bounds user-controlled list sizes and page offsets", () => {
    const options = parseReviewListOptions(
      new URLSearchParams("limit=99999&page=-2&severity=WRONG"),
    );
    expect(options.limit).toBe(25);
    expect(options.offset).toBe(0);
    expect(options.severity).toBeUndefined();
  });
  it("retains filters when paging", () => {
    const options = parseReviewListOptions(
      new URLSearchParams("limit=50&severity=CRITICAL&search=admin&resolved=yes"),
    );
    const url = new URL(reviewListUrl("/actions/evidence", options, 2), "https://example.invalid");
    expect(url.searchParams.get("page")).toBe("2");
    expect(url.searchParams.get("severity")).toBe("CRITICAL");
    expect(url.searchParams.get("resolved")).toBe("yes");
    expect(url.searchParams.get("search")).toBe("admin");
  });
  it("never upgrades an unknown evidence state to observed", () => {
    expect(classifyStoredEvidenceState("unknown")).toBe("UNKNOWN");
    expect(classifyStoredEvidenceState("observed")).toBe("OBSERVED");
    expect(classifyStoredEvidenceState("unexpected")).toBe("UNKNOWN");
  });
});
