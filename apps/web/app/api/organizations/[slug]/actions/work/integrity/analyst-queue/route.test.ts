import { WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { beforeEach, describe, expect, it, vi } from "vitest";

const access = vi.hoisted(() => ({
  requireOrganizationAccess: vi.fn(),
  loadIntegrityCases: vi.fn(),
}));
vi.mock("../../../../../../../../lib/organizations", () => ({
  requireOrganizationAccess: access.requireOrganizationAccess,
}));
vi.mock("../../../../../../../../lib/work-integrity-cases", () => ({
  loadIntegrityCases: access.loadIntegrityCases,
}));
import { NextRequest } from "next/server";
import { GET } from "./route";

const context = { params: Promise.resolve({ slug: "tenant-a" }) };
const url = (query = "") => new NextRequest(
  `https://cyberpilot.invalid/api/organizations/tenant-a/actions/work/integrity/analyst-queue${query}`,
);
const caseRow = {
  key: JSON.stringify(["task-1", "DONE_WITHOUT_COMPLETION", "resource-1"]),
  workItemId: "task-1", resourceId: "resource-1",
  code: "DONE_WITHOUT_COMPLETION", taskStatus: "DONE", taskRevision: 1,
  severity: "critical", diagnostic: "Missing completion",
  recommendation: "Investigate", state: "UNREVIEWED",
  reviewEventId: null, reviewedAt: null, reviewedRevision: null,
  reviewerUserId: null, reviewRationale: null, reviewReference: null,
  completeCoverage: true, historicalOnly: false,
};
const report = {
  generatedAt: "2026-10-31T10:00:00.000Z",
  filters: { state: "ALL", severity: "ALL", search: "",
    limit: 25, cursor: null, includeInfo: true, includeHistorical: true },
  totalWorkItemsExamined: 1, cases: [caseRow],
  summary: { totalOnPage: 1, unreviewed: 1, investigating: 0,
    acknowledged: 0, dismissed: 0, reopened: 0, stale: 0,
    noLongerDetected: 0, critical: 1, attention: 0, informational: 0,
    partialCoverage: 0, reviewed: 0, historicalOnly: 0 },
  nextCursor: null, reviewEventsFetched: 0,
  historyComplete: true, limitations: [],
};
beforeEach(() => {
  vi.resetAllMocks();
  access.requireOrganizationAccess.mockResolvedValue({
    session: { user: { id: "user-a" } },
    membership: { role: "OWNER", organization: { id: "org-a", slug: "tenant-a" } },
  });
  access.loadIntegrityCases.mockResolvedValue(report);
});
describe("authenticated live analyst queue endpoint", () => {
  it("returns tenant-scoped JSON", async () => {
    const response = await GET(url(), context);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.organizationId).toBe("org-a");
  });
  it("loads cases under authenticated user scope", async () => {
    await GET(url(), context);
    expect(access.loadIntegrityCases).toHaveBeenCalledWith(
      { organizationId: "org-a", userId: "user-a", role: "OWNER" }, {},
    );
  });
  it("prevents shared caching", async () => {
    const response = await GET(url(), context);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  });
  it("sets nosniff header", async () => {
    const response = await GET(url(), context);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });
  it("returns bounded case data", async () => {
    const response = await GET(url(), context);
    const body = await response.json();
    expect(body.entries).toHaveLength(1);
    expect(body.entries[0].priority).toBe("P0");
  });
  it("returns evidence gaps", async () => {
    const response = await GET(url(), context);
    const body = await response.json();
    expect(body.entries[0].missingEvidence).toContain("reviewEventId");
  });
  it("exports CSV", async () => {
    const response = await GET(url("?format=csv"), context);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/csv");
    expect(await response.text()).toContain("task-1");
  });
  it("adds safe attachment disposition", async () => {
    const response = await GET(url("?format=csv"), context);
    expect(response.headers.get("content-disposition")).toContain("attachment");
  });
  it("supports JSON format", async () => {
    const response = await GET(url("?format=json"), context);
    expect(response.headers.get("content-type")).toContain("application/json");
  });
  it("rejects unknown format", async () => {
    expect((await GET(url("?format=xml"), context)).status).toBe(400);
  });
  it("rejects unknown query keys", async () => {
    expect((await GET(url("?organizationId=org-b"), context)).status).toBe(400);
  });
  it("rejects repeated filters", async () => {
    expect((await GET(url("?priority=P0&priority=P1"), context)).status).toBe(400);
  });
  it("rejects repeated format", async () => {
    expect((await GET(url("?format=json&format=csv"), context)).status).toBe(400);
  });
  it("rejects malformed priority", async () => {
    expect((await GET(url("?priority=P9"), context)).status).toBe(400);
  });
  it("rejects malformed offset", async () => {
    expect((await GET(url("?offset=-1"), context)).status).toBe(400);
  });
  it("rejects excessive page size", async () => {
    expect((await GET(url("?pageSize=101"), context)).status).toBe(400);
  });
  it("accepts bounded filters", async () => {
    const response = await GET(url("?priority=P0&reviewed=NO&pageSize=10"), context);
    expect(response.status).toBe(200);
    expect((await response.json()).totalMatching).toBe(1);
  });
  it("passes original case filters through", async () => {
    await GET(url("?limit=50&includeHistorical=true"), context);
    expect(access.loadIntegrityCases).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: "org-a" }),
      expect.objectContaining({ limit: "50", includeHistorical: "true" }),
    );
  });
  it("maps access errors to forbidden", async () => {
    access.loadIntegrityCases.mockRejectedValue(new WorkInputError("FORBIDDEN", "No access"));
    expect((await GET(url(), context)).status).toBe(403);
  });
  it("maps invalid case filters to bad request", async () => {
    access.loadIntegrityCases.mockRejectedValue(new WorkInputError("INVALID", "Invalid filter"));
    expect((await GET(url(), context)).status).toBe(400);
  });
  it("does not leak internal errors", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    access.loadIntegrityCases.mockRejectedValue(new Error("private database details"));
    const response = await GET(url(), context);
    expect(response.status).toBe(500);
    expect(JSON.stringify(await response.json())).not.toContain("private database details");
    spy.mockRestore();
  });
  it("does not load cases on unknown query", async () => {
    await GET(url("?evil=1"), context);
    expect(access.loadIntegrityCases).not.toHaveBeenCalled();
  });
  it("requires organization membership before loading data", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    access.requireOrganizationAccess.mockRejectedValue(new Error("No session"));
    expect((await GET(url(), context)).status).toBe(500);
    expect(access.loadIntegrityCases).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
