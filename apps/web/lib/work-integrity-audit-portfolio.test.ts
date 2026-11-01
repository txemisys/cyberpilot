import { describe, expect, it } from "vitest";
import type { AuditChainReport } from "./work-integrity-audit-chain";
import {
  buildAuditPortfolio, parseAuditPortfolioOptions, portfolioCoverage,
  portfolioNextAction, auditPortfolioCsv,
} from "./work-integrity-audit-portfolio";

const filters = parseAuditPortfolioOptions({});
const base = (id: string, patch: Partial<AuditChainReport> = {}): AuditChainReport => ({
  organizationId: "org-a", workItemId: id, workTitle: "Review work",
  currentRevision: 2, generatedAt: "2026-10-01T00:00:00.000Z",
  bounded: false, historyComplete: true, recordsRead: 1,
  malformedRecords: 0, problems: [], cases: [{
    caseKey: JSON.stringify([id, "DONE_WITHOUT_COMPLETION", id]),
    workItemId: id, code: "DONE_WITHOUT_COMPLETION", resourceId: id,
    eventCount: 1, rootCount: 1, headCount: 1, latestEventId: "audit-a",
    latestDecision: "INVESTIGATE", latestRevision: 2,
    isCurrentRevision: true, chainLength: 1, completeHistory: true,
    errors: 0, warnings: 0, unknowns: 0, eventIds: [],
  }],
  totals: { cases: 1, errors: 0, warnings: 0, unknowns: 0 },
  limitations: [], ...patch,
});
const work = (id: string, title = "Review work") => ({
  id, title, status: "IN_PROGRESS", revision: 2,
  assigneeUserId: "user-1", dueAt: null,
});
function portfolio(items = [work("work-1")], reports = [base("work-1")],
  options = filters, nextCursor: string | null = null) {
  return buildAuditPortfolio("org-a", "2026-10-02T00:00:00.000Z",
    options, items, new Map(reports.map(r => [r.workItemId, r])), nextCursor);
}
describe("audit portfolio query security and bounds", () => {
  it("accepts defaults with a bounded first page", () => {
    expect(filters).toEqual({
      limit: 20, cursor: null, historyLimit: 500, onlyReviewed: false,
    });
  });
  it("accepts supported page size and cursor", () => {
    expect(parseAuditPortfolioOptions({
      limit: "50", cursor: "work-123", onlyReviewed: "true", historyLimit: "2000",
    })).toMatchObject({
      limit: 50, cursor: "work-123", onlyReviewed: true, historyLimit: 2000,
    });
  });
  it.each([
    { limit: "21" },
    { limit: "-1" },
    { cursor: "../../escape" },
    { cursor: "bad" },
    { historyLimit: "999999" },
    { onlyReviewed: "yes" },
    { organizationId: "other" },
  ])("rejects invalid or unauthorized portfolio options %j", options => {
    expect(() => parseAuditPortfolioOptions(options)).toThrow();
  });
  it("refuses foreign organization audit data", () => {
    expect(() => portfolio([work("work-1")], [
      base("work-1", { organizationId: "org-b" }),
    ])).toThrow(/cross-tenant/);
  });
  it("refuses a missing per-item audit result", () => {
    expect(() => portfolio([work("work-1")], [])).toThrow();
  });
  it("refuses mismatched audit resource identities", () => {
    expect(() => buildAuditPortfolio("org-a", "2026-10-02T00:00:00.000Z",
      filters, [work("work-1")], new Map([
        ["work-1", base("work-other")],
      ]), null)).toThrow(/cross-tenant/);
  });
});
describe("audit portfolio review coverage", () => {
  it("identifies internally complete review chains without security attestation", () => {
    expect(portfolioCoverage(base("work-1"))).toBe("COMPLETE");
    expect(portfolio().rows[0]?.action).toMatch(/verify the underlying control/);
  });
  it("separates work with no recorded reviews", () => {
    const missing = base("work-1", {
      recordsRead: 0, cases: [],
      totals: { cases: 0, errors: 0, warnings: 0, unknowns: 0 },
    });
    expect(portfolioCoverage(missing)).toBe("NO_REVIEW");
    expect(portfolio([work("work-1")], [missing]).counts.noReview).toBe(1);
  });
  it("shows incomplete history separately from integrity faults", () => {
    expect(portfolioCoverage(base("work-1", { historyComplete: false })))
      .toBe("PARTIAL");
    expect(portfolioNextAction({
      reviewCoverage: "PARTIAL", errors: 0, warnings: 0,
    })).toMatch(/additional authorized audit history/);
  });
  it("prioritizes inconsistent audit links", () => {
    const inconsistent = base("work-1", {
      totals: { cases: 1, errors: 2, warnings: 1, unknowns: 0 },
      historyComplete: false,
    });
    expect(portfolioCoverage(inconsistent)).toBe("INCONSISTENT");
    expect(portfolio([work("work-1")], [inconsistent]).counts.errors).toBe(2);
  });
  it("does not treat invalid metadata as complete", () => {
    expect(portfolioCoverage(base("work-1", {
      malformedRecords: 1,
    }))).toBe("INCONSISTENT");
  });
  it("keeps uncertain link counts in portfolio summary", () => {
    const uncertain = base("work-1", {
      bounded: true, historyComplete: false,
      totals: { cases: 1, errors: 0, warnings: 0, unknowns: 3 },
    });
    const result = portfolio([work("work-1")], [uncertain]);
    expect(result.counts.unknowns).toBe(3);
    expect(result.counts.partial).toBe(1);
  });
  it("filters unreviewed entries only after reading the bounded work page", () => {
    const noReview = base("work-2", {
      recordsRead: 0, cases: [], totals: {
        cases: 0, errors: 0, warnings: 0, unknowns: 0,
      },
    });
    const options = { ...filters, onlyReviewed: true };
    const result = portfolio(
      [work("work-1"), work("work-2")],
      [base("work-1"), noReview], options,
    );
    expect(result.examinedWorkItems).toBe(2);
    expect(result.rows).toHaveLength(1);
    expect(result.limitations.join(" ")).toMatch(/after the bounded source page/);
  });
  it("sorts source integrity faults ahead of missing reviews", () => {
    const incomplete = base("work-2", {
      recordsRead: 0, cases: [], totals: {
        cases: 0, errors: 0, warnings: 0, unknowns: 0,
      },
    });
    const bad = base("work-1", {
      historyComplete: false,
      totals: { cases: 1, errors: 1, warnings: 0, unknowns: 0 },
    });
    const result = portfolio(
      [work("work-2"), work("work-1")], [incomplete, bad],
    );
    expect(result.rows.map(row => row.workItemId))
      .toEqual(["work-1", "work-2"]);
  });
  it("preserves continuation indication without claiming global coverage", () => {
    const result = portfolio([work("work-1")], [base("work-1")],
      filters, "work-1");
    expect(result.nextCursor).toBe("work-1");
    expect(result.limitations.join(" ")).toMatch(/Additional work-item pages/);
  });
  it("provides safe CSV against formula injection in work titles", () => {
    const result = portfolio([work("work-1", "=HYPERLINK(1)")]);
    const csv = auditPortfolioCsv(result);
    expect(csv).toContain("'=HYPERLINK(1)");
    expect(csv).toContain("reviewCoverage");
    expect(csv.endsWith("\r\n")).toBe(true);
  });
});
