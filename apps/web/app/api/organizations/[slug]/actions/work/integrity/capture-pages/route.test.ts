import { beforeEach, describe, expect, it, vi } from "vitest";
import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
const mocks = vi.hoisted(() => ({
  requireOrganizationAccess: vi.fn(),
  loadIntegrityCases: vi.fn(),
}));
vi.mock("../../../../../../../../lib/organizations", () => ({
  requireOrganizationAccess: mocks.requireOrganizationAccess,
}));
vi.mock("../../../../../../../../lib/work-integrity-cases", () => ({
  loadIntegrityCases: mocks.loadIntegrityCases,
}));
import { NextRequest } from "next/server";
import { GET } from "./route";
import { parseCaseSnapshot } from "../../../../../../../../lib/work-integrity-snapshots";

const context = { params: Promise.resolve({ slug: "tenant-a" }) };
const request = (query = "") => new NextRequest(
  `https://cyberpilot.invalid/api/organizations/tenant-a/actions/work/integrity/capture-pages${query}`,
);
const row = {
  key: JSON.stringify(["work-a", "DONE_WITHOUT_COMPLETION", "work-a"]),
  workItemId: "work-a", resourceId: "work-a",
  code: "DONE_WITHOUT_COMPLETION", taskStatus: "DONE",
  taskRevision: 1, severity: "critical",
  diagnostic: "Missing completion", recommendation: "Investigate",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null,
  reviewRationale: null, reviewReference: null,
  completeCoverage: true, historicalOnly: false,
};
const page = {
  generatedAt: "2026-10-31T10:00:00.000Z",
  filters: {
    state: "ALL", severity: "ALL", search: "",
    limit: 50, cursor: null, includeInfo: true, includeHistorical: true,
  },
  totalWorkItemsExamined: 1, cases: [row],
  summary: {
    totalOnPage: 1, unreviewed: 1, investigating: 0,
    acknowledged: 0, dismissed: 0, reopened: 0,
    stale: 0, noLongerDetected: 0, critical: 1,
    attention: 0, informational: 0, partialCoverage: 0,
    reviewed: 0, historicalOnly: 0,
  },
  nextCursor: null, reviewEventsFetched: 0,
  historyComplete: true, limitations: [],
};
beforeEach(() => {
  vi.resetAllMocks();
  mocks.requireOrganizationAccess.mockResolvedValue({
    session: { user: { id: "user-a" } },
    membership: {
      role: "OWNER", organization: { id: "org-a", slug: "tenant-a" },
    },
  });
  mocks.loadIntegrityCases.mockResolvedValue(page);
});
describe("authenticated bounded multi-page capture API", () => {
  it("returns directly comparable snapshot JSON", async () => {
    const response = await GET(request(), context);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(parseCaseSnapshot(body).cases).toHaveLength(1);
  });
  it("reports capture traversal metadata", async () => {
    const body = await (await GET(request(), context)).json();
    expect(body.traversal.pagesRead).toBe(1);
    expect(body.traversal.workItemsExamined).toBe(1);
    expect(body.traversal.hasMore).toBe(false);
  });
  it("preserves trusted tenant identity", async () => {
    const body = await (await GET(request(), context)).json();
    expect(body.organizationId).toBe("org-a");
  });
  it("uses authenticated work scope", async () => {
    await GET(request(), context);
    expect(mocks.loadIntegrityCases).toHaveBeenCalledWith({
      organizationId: "org-a", userId: "user-a", role: "OWNER",
    }, { limit: "50", includeInfo: "true", includeHistorical: "true" });
  });
  it("supports explicit page limit", async () => {
    await GET(request("?maxPages=1"), context);
    expect(mocks.loadIntegrityCases).toHaveBeenCalledTimes(1);
  });
  it("supports explicit page size", async () => {
    await GET(request("?pageSize=100"), context);
    expect(mocks.loadIntegrityCases).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: "org-a" }),
      expect.objectContaining({ limit: "100" }),
    );
  });
  it("rejects excessive page traversal", async () => {
    expect((await GET(request("?maxPages=11"), context)).status).toBe(400);
  });
  it("rejects zero page traversal", async () => {
    expect((await GET(request("?maxPages=0"), context)).status).toBe(400);
  });
  it("rejects unknown parameters", async () => {
    expect((await GET(request("?organizationId=foreign"), context)).status).toBe(400);
  });
  it("rejects duplicate parameters", async () => {
    expect((await GET(request("?maxPages=1&maxPages=2"), context)).status).toBe(400);
  });
  it("rejects malformed booleans", async () => {
    expect((await GET(request("?includeHistorical=yes"), context)).status).toBe(400);
  });
  it("rejects invalid page size", async () => {
    expect((await GET(request("?pageSize=1000"), context)).status).toBe(400);
  });
  it("prevents shared cache of tenant data", async () => {
    const response = await GET(request(), context);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  });
  it("sets nosniff header", async () => {
    const response = await GET(request(), context);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });
  it("downloads as a JSON attachment", async () => {
    const response = await GET(request(), context);
    expect(response.headers.get("content-disposition")).toContain("attachment");
  });
  it("rejects a forbidden work role", async () => {
    mocks.loadIntegrityCases.mockRejectedValue(
      new WorkInputError("FORBIDDEN", "No work access"),
    );
    expect((await GET(request(), context)).status).toBe(403);
  });
  it("does not expose backend error details", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.loadIntegrityCases.mockRejectedValue(new Error("database secret"));
    const response = await GET(request(), context);
    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).not.toContain("database secret");
    spy.mockRestore();
  });
  it("does not load cases when membership lookup fails", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.requireOrganizationAccess.mockRejectedValue(new Error("No membership"));
    expect((await GET(request(), context)).status).toBe(500);
    expect(mocks.loadIntegrityCases).not.toHaveBeenCalled();
    spy.mockRestore();
  });
  it("does not fabricate completion if more pages remain", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, nextCursor: "opaque-next",
    });
    const body = await (await GET(request("?maxPages=1"), context)).json();
    expect(body.complete).toBe(false);
    expect(body.traversal.hasMore).toBe(true);
  });
  it("does not mark partial linked coverage complete", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, cases: [{ ...row, completeCoverage: false }],
    });
    const body = await (await GET(request(), context)).json();
    expect(body.complete).toBe(false);
  });
  it("does not mark incomplete audit history complete", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, historyComplete: false,
    });
    const body = await (await GET(request(), context)).json();
    expect(body.complete).toBe(false);
  });
  it("returns no case data on invalid input", async () => {
    const response = await GET(request("?maxPages=1000"), context);
    expect(response.status).toBe(400);
    expect(JSON.stringify(await response.json())).not.toContain("work-a");
    expect(mocks.loadIntegrityCases).not.toHaveBeenCalled();
  });
});
