import { describe, expect, it } from "vitest";
import {
  buildProviderHistory, buildProviderFollowUps,
  classifyProviderTransition, parseProviderHistoryQuery,
} from "./work-integrity-provider-history";

const checkedAt = new Date("2026-11-03T10:00:00Z");
const base = {
  id: "check-0001", evidenceId: "evidence-12345",
  provider: "GOOGLE_WORKSPACE",
  subject: "admin@example.invalid",
  controlId: "google_workspace.user_2sv",
  outcome: "PASS", checkedAt, providerObservedAt: checkedAt,
  observationDigest: "a".repeat(64),
  responseDigest: "b".repeat(64),
  failureCode: null,
};
const next = (id: string, outcome: string, minutes: number) => ({
  ...base, id, outcome,
  checkedAt: new Date(checkedAt.getTime() + minutes * 60000),
});
describe("provider history transitions", () => {
  it("classifies the first provider observation", () => {
    expect(classifyProviderTransition(null, base)).toBe("FIRST_OBSERVATION");
  });
  it.each([
    ["PASS", "FAIL", "PASS_TO_FAIL"],
    ["FAIL", "PASS", "FAIL_TO_PASS"],
    ["PROVIDER_ERROR", "PASS", "RECOVERED_PROVIDER"],
    ["PASS", "PROVIDER_ERROR", "PROVIDER_INTERRUPTED"],
    ["PASS", "INCONCLUSIVE", "BECAME_INCONCLUSIVE"],
    ["INCONCLUSIVE", "PASS", "RESOLVED_INCONCLUSIVE"],
    ["PASS", "PASS", "UNCHANGED"],
  ])("classifies %s to %s", (before, after, expected) => {
    expect(classifyProviderTransition({
      ...base, outcome: before,
    }, { ...base, outcome: after })).toBe(expected);
  });
  it("sorts history chronologically and retains prior IDs", () => {
    const records = [
      next("check-0003", "PASS", 30),
      next("check-0002", "FAIL", 15),
      base,
    ];
    const points = buildProviderHistory(records);
    expect(points.map(x => x.id)).toEqual([
      "check-0001", "check-0002", "check-0003",
    ]);
    expect(points.map(x => x.transition)).toEqual([
      "FIRST_OBSERVATION", "PASS_TO_FAIL", "FAIL_TO_PASS",
    ]);
    expect(points[1]?.previousCheckId).toBe("check-0001");
    expect(points[2]?.intervalMinutes).toBe(15);
  });
  it("retains predecessors across pagination boundaries", () => {
    const prior = new Map([[base.evidenceId, base]]);
    const points = buildProviderHistory([
      next("check-0002", "FAIL", 15),
    ], prior);
    expect(points[0]?.transition).toBe("PASS_TO_FAIL");
    expect(points[0]?.previousCheckId).toBe(base.id);
  });
  it("keeps evidence records independent", () => {
    const other = {
      ...base, id: "other-check-0001",
      evidenceId: "other-evidence-12345",
    };
    const points = buildProviderHistory([base, other]);
    expect(points.every(x => x.transition === "FIRST_OBSERVATION")).toBe(true);
  });
  it("detects changed evidence digests", () => {
    const points = buildProviderHistory([
      base, {
        ...next("check-0002", "PASS", 15),
        observationDigest: "c".repeat(64),
      },
    ]);
    expect(points[1]?.observationChanged).toBe(true);
  });
});
describe("provider history follow-ups", () => {
  it("prioritizes failed controls over provider errors", () => {
    const failed = buildProviderHistory([
      base, next("check-0002", "FAIL", 15),
    ]);
    const other = buildProviderHistory([
      { ...base, id: "other-check-0001",
        evidenceId: "other-evidence-12345",
        outcome: "PROVIDER_ERROR" },
    ]);
    const followUps = buildProviderFollowUps([...other, ...failed]);
    expect(followUps[0]?.priority).toBe("CONTROL_FAILURE");
    expect(followUps[0]?.lastPassingCheckId).toBe(base.id);
    expect(followUps[0]?.consecutiveNonPassingChecks).toBe(1);
  });
  it("clears investigation after a passing check", () => {
    const points = buildProviderHistory([
      base, next("check-0002", "FAIL", 15),
      next("check-0003", "PASS", 30),
    ]);
    const followUp = buildProviderFollowUps(points)[0];
    expect(followUp?.needsInvestigation).toBe(false);
    expect(followUp?.firstNonPassingAt).toBeNull();
  });
});
describe("provider history query", () => {
  it("applies bounded defaults", () => {
    expect(parseProviderHistoryQuery({
      taskId: "review-task-12345",
    })).toMatchObject({ offset: 0, limit: 50 });
  });
  it.each([
    { offset: -1 }, { offset: "0" },
    { limit: 0 }, { limit: 201 },
    { from: "yesterday" },
    { from: "2026-11-04T00:00:00Z",
      to: "2026-11-03T00:00:00Z" },
    { unexpected: true },
  ])("rejects invalid history query %j", patch => {
    expect(() => parseProviderHistoryQuery({
      taskId: "review-task-12345", ...patch,
    })).toThrow();
  });
});
