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
  `https://cyberpilot.invalid/api/organizations/tenant-a/actions/work/integrity/snapshot${query}`,
);
const record = {
  key: JSON.stringify(["task-a", "DONE_WITHOUT_COMPLETION", "resource-a"]),
  workItemId: "task-a", resourceId: "resource-a",
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
    limit: 25, cursor: null, includeInfo: true, includeHistorical: true,
  },
  totalWorkItemsExamined: 1, cases: [record],
  summary: {
    totalOnPage: 1, unreviewed: 1, investigating: 0,
    acknowledged: 0, dismissed: 0, reopened: 0, stale: 0,
    noLongerDetected: 0, critical: 1, attention: 0,
    informational: 0, partialCoverage: 0, reviewed: 0,
    historicalOnly: 0,
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
describe("authenticated operational case capture", () => {
  it("exports JSON in the comparison snapshot schema", async () => {
    const response = await GET(request(), context);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(parseCaseSnapshot(body).cases).toHaveLength(1);
  });
  it("uses authenticated tenant ID rather than query input", async () => {
    const response = await GET(request(), context);
    expect((await response.json()).organizationId).toBe("org-a");
  });
  it("uses authenticated work scope", async () => {
    await GET(request(), context);
    expect(mocks.loadIntegrityCases).toHaveBeenCalledWith({
      organizationId: "org-a", userId: "user-a", role: "OWNER",
    }, { includeInfo: "true", includeHistorical: "true" });
  });
  it("returns a safe attachment", async () => {
    const response = await GET(request(), context);
    expect(response.headers.get("content-disposition")).toContain("attachment");
    expect(response.headers.get("content-type")).toContain("application/json");
  });
  it("disables shared caching", async () => {
    const response = await GET(request(), context);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  });
  it("sets nosniff header", async () => {
    const response = await GET(request(), context);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });
  it("rejects unknown query parameters", async () => {
    expect((await GET(request("?organizationId=foreign"), context)).status).toBe(400);
  });
  it("rejects repeated limit", async () => {
    expect((await GET(request("?limit=10&limit=50"), context)).status).toBe(400);
  });
  it("rejects repeated cursor", async () => {
    expect((await GET(request("?cursor=a&cursor=b"), context)).status).toBe(400);
  });
  it("rejects analyst-only priority filter", async () => {
    expect((await GET(request("?priority=P0"), context)).status).toBe(400);
  });
  it("rejects analyst-only offset", async () => {
    expect((await GET(request("?offset=1"), context)).status).toBe(400);
  });
  it("rejects malformed case limit", async () => {
    mocks.loadIntegrityCases.mockRejectedValue(
      new WorkInputError("INVALID", "Invalid limit"),
    );
    expect((await GET(request("?limit=999"), context)).status).toBe(400);
  });
  it("preserves cursor selection in the source metadata", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, filters: { ...page.filters, cursor: "opaque-cursor" },
      nextCursor: "another-cursor",
    });
    const response = await GET(request("?cursor=opaque-cursor"), context);
    const body = await response.json();
    expect(JSON.parse(body.source).cursor).toBe("opaque-cursor");
    expect(body.complete).toBe(false);
  });
  it("does not claim completeness for partial linked records", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, cases: [{ ...record, completeCoverage: false }],
    });
    const body = await (await GET(request(), context)).json();
    expect(body.complete).toBe(false);
  });
  it("does not claim completeness for truncated audit history", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, historyComplete: false,
    });
    const body = await (await GET(request(), context)).json();
    expect(body.complete).toBe(false);
  });
  it("does not claim completeness when filters exclude severities", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, filters: { ...page.filters, severity: "critical" },
    });
    const body = await (await GET(request("?severity=critical"), context)).json();
    expect(body.complete).toBe(false);
  });
  it("does not claim completeness when filters exclude info", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, filters: { ...page.filters, includeInfo: false },
    });
    const body = await (await GET(request("?includeInfo=false"), context)).json();
    expect(body.complete).toBe(false);
  });
  it("does not claim completeness when historical cases are excluded", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, filters: { ...page.filters, includeHistorical: false },
    });
    const body = await (await GET(request("?includeHistorical=false"), context)).json();
    expect(body.complete).toBe(false);
  });
  it("does not claim completeness when work page continues", async () => {
    mocks.loadIntegrityCases.mockResolvedValue({
      ...page, nextCursor: "next",
    });
    const body = await (await GET(request(), context)).json();
    expect(body.complete).toBe(false);
  });
  it("does not return data after forbidden access", async () => {
    mocks.loadIntegrityCases.mockRejectedValue(
      new WorkInputError("FORBIDDEN", "No work access"),
    );
    const response = await GET(request(), context);
    expect(response.status).toBe(403);
    expect(JSON.stringify(await response.json())).not.toContain("task-a");
  });
  it("does not load cases when organization lookup fails", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.requireOrganizationAccess.mockRejectedValue(new Error("No membership"));
    expect((await GET(request(), context)).status).toBe(500);
    expect(mocks.loadIntegrityCases).not.toHaveBeenCalled();
    spy.mockRestore();
  });
  it("does not leak unexpected backend errors", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.loadIntegrityCases.mockRejectedValue(new Error("database secret"));
    const response = await GET(request(), context);
    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).not.toContain("database secret");
    spy.mockRestore();
  });
  it("preserves timestamp from actual case load", async () => {
    const body = await (await GET(request(), context)).json();
    expect(body.capturedAt).toBe(page.generatedAt);
  });
  it("does not mutate source case records", async () => {
    const original = JSON.stringify(page);
    await GET(request(), context);
    expect(JSON.stringify(page)).toBe(original);
  });
});
