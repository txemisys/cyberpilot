import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ requireOrganizationAccess: vi.fn() }));
vi.mock("../../../../../../../../lib/organizations", () => ({
  requireOrganizationAccess: mocks.requireOrganizationAccess,
}));
import { NextRequest } from "next/server";
import { POST } from "./route";

const context = { params: Promise.resolve({ slug: "tenant-a" }) };
const row = {
  key: JSON.stringify(["work-a", "DONE_WITHOUT_COMPLETION", "work-a"]),
  workItemId: "work-a", resourceId: "work-a",
  code: "DONE_WITHOUT_COMPLETION", taskStatus: "DONE",
  taskRevision: 1, severity: "attention",
  diagnostic: "Missing completion", recommendation: "Investigate",
  state: "UNREVIEWED", reviewEventId: null, reviewedAt: null,
  reviewedRevision: null, reviewerUserId: null, reviewRationale: null,
  reviewReference: null, completeCoverage: true, historicalOnly: false,
};
const data = {
  before: {
    organizationId: "org-a", capturedAt: "2026-10-30T10:00:00.000Z",
    source: "test", complete: true, cases: [],
  },
  after: {
    organizationId: "org-a", capturedAt: "2026-10-31T10:00:00.000Z",
    source: "test", complete: true, cases: [row],
  },
};
function request(
  value: unknown = data, format = "", headers: Record<string, string> = {},
): NextRequest {
  return new NextRequest(
    `https://cyberpilot.invalid/api/organizations/tenant-a/actions/work/integrity/compare${format}`,
    {
      method: "POST", body: JSON.stringify(value),
      headers: { "content-type": "application/json", ...headers },
    },
  );
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.requireOrganizationAccess.mockResolvedValue({
    session: { user: { id: "user-a" } },
    membership: {
      role: "OWNER", organization: { id: "org-a", slug: "tenant-a" },
    },
  });
});
describe("authenticated offline capture comparison API", () => {
  it("returns a comparison for matching tenant", async () => {
    const response = await POST(request(), context);
    expect(response.status).toBe(200);
    expect((await response.json()).counts.NEW).toBe(1);
  });
  it("uses trusted membership identity", async () => {
    const response = await POST(request(), context);
    expect((await response.json()).organizationId).toBe("org-a");
  });
  it("requires organization membership", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.requireOrganizationAccess.mockRejectedValue(new Error("No session"));
    expect((await POST(request(), context)).status).toBe(500);
    spy.mockRestore();
  });
  it("rejects foreign before capture", async () => {
    const input = structuredClone(data);
    input.before.organizationId = "org-b";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects foreign after capture", async () => {
    const input = structuredClone(data);
    input.after.organizationId = "org-b";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects forged tenant in both captures", async () => {
    const input = structuredClone(data);
    input.before.organizationId = "org-b";
    input.after.organizationId = "org-b";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects reverse chronology", async () => {
    const input = structuredClone(data);
    input.before.capturedAt = "2026-11-01T10:00:00.000Z";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects malformed body", async () => {
    expect((await POST(request(null), context)).status).toBe(400);
  });
  it("rejects unknown export format", async () => {
    expect((await POST(request(data, "?format=xml"), context)).status).toBe(400);
  });
  it("rejects unknown query parameter", async () => {
    expect((await POST(request(data, "?tenant=org-b"), context)).status).toBe(400);
  });
  it("rejects repeated export format", async () => {
    expect((await POST(request(data, "?format=csv&format=json"), context)).status).toBe(400);
  });
  it("returns CSV on request", async () => {
    const response = await POST(request(data, "?format=csv"), context);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/csv");
    expect(await response.text()).toContain("DONE_WITHOUT_COMPLETION");
  });
  it("sets safe attachment disposition", async () => {
    const response = await POST(request(data, "?format=csv"), context);
    expect(response.headers.get("content-disposition")).toContain("attachment");
  });
  it("sets private cache headers", async () => {
    const response = await POST(request(), context);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  });
  it("sets nosniff header", async () => {
    const response = await POST(request(), context);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });
  it("rejects incorrect content type", async () => {
    const response = await POST(request(data, "", { "content-type": "text/plain" }), context);
    expect(response.status).toBe(400);
  });
  it("accepts JSON with charset", async () => {
    const response = await POST(request(data, "", {
      "content-type": "application/json; charset=utf-8",
    }), context);
    expect(response.status).toBe(200);
  });
  it("rejects oversized declared body", async () => {
    const response = await POST(request(data, "", {
      "content-length": "4000001",
    }), context);
    expect(response.status).toBe(400);
  });
  it("rejects invalid declared body length", async () => {
    const response = await POST(request(data, "", {
      "content-length": "not-a-number",
    }), context);
    expect(response.status).toBe(400);
  });
  it("returns a bounded empty comparison", async () => {
    const input = structuredClone(data);
    input.after.cases = [];
    const response = await POST(request(input), context);
    expect(response.status).toBe(200);
    expect((await response.json()).changes).toHaveLength(0);
  });
  it("does not treat partial captures as confirmed new cases", async () => {
    const input = structuredClone(data);
    input.before.complete = false;
    const response = await POST(request(input), context);
    const body = await response.json();
    expect(body.counts.INDETERMINATE).toBe(1);
    expect(body.counts.NEW).toBe(0);
  });
  it("does not return a raw stack trace on malformed data", async () => {
    const response = await POST(request({ invalid: true }), context);
    const body = await response.json();
    expect(body.code).toBe("INVALID");
    expect(JSON.stringify(body)).not.toContain("at compareIntegrityCaptures");
  });
  it("rejects users without work permissions", async () => {
    mocks.requireOrganizationAccess.mockResolvedValue({
      session: { user: { id: "user-a" } },
      membership: {
        role: "UNKNOWN_ROLE",
        organization: { id: "org-a", slug: "tenant-a" },
      },
    });
    expect((await POST(request(), context)).status).toBe(403);
  });
  it("does not reveal another tenant's cases", async () => {
    const response = await POST(request({
      before: { ...data.before, organizationId: "org-b" },
      after: { ...data.after, organizationId: "org-b" },
    }), context);
    expect(response.status).toBe(400);
    expect(JSON.stringify(await response.json())).not.toContain("work-a");
  });
  it("returns only generic errors on unexpected failure", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    mocks.requireOrganizationAccess.mockRejectedValue(new Error("secret backend detail"));
    const response = await POST(request(), context);
    expect(JSON.stringify(await response.json())).not.toContain("secret backend detail");
    spy.mockRestore();
  });
});

describe("capture comparison endpoint privacy and deterministic results", () => {
  it("preserves stable JSON output for equivalent requests", async () => {
    const a = await POST(request(), context);
    const b = await POST(request(), context);
    expect(await a.json()).toEqual(await b.json());
  });
  it("does not include private audit credentials", async () => {
    const response = await POST(request(), context);
    const body = JSON.stringify(await response.json());
    expect(body).not.toContain("sessionToken");
    expect(body).not.toContain("password");
  });
  it("rejects snapshot with missing organization", async () => {
    const input = structuredClone(data);
    input.before.organizationId = "";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects malformed capture source", async () => {
    const input = structuredClone(data);
    input.after.source = "";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects malformed case key", async () => {
    const input = structuredClone(data);
    input.after.cases[0].key = "forged-key";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects invalid case severity", async () => {
    const input = structuredClone(data);
    input.after.cases[0].severity = "untrusted" as "attention";
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("rejects duplicate case identities", async () => {
    const input = structuredClone(data);
    input.after.cases.push(structuredClone(row));
    expect((await POST(request(input), context)).status).toBe(400);
  });
  it("does not create an audit decision when comparing", async () => {
    const response = await POST(request(), context);
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.changes[0]?.kind).toBe("NEW");
    expect(result.warnings.some((line: string) =>
      line.includes("user") || line.includes("caller"))).toBe(true);
  });
  it("does not allow comparison of foreign tenant despite valid format", async () => {
    const foreign = structuredClone(data);
    foreign.before.organizationId = "org-foreign";
    foreign.after.organizationId = "org-foreign";
    const response = await POST(request(foreign, "?format=csv"), context);
    expect(response.status).toBe(400);
    expect(response.headers.get("content-disposition")).toBeNull();
  });
  it("returns JSON when format is explicitly selected", async () => {
    const response = await POST(request(data, "?format=json"), context);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
  });
  it("rejects case data with invalid revision", async () => {
    const input = structuredClone(data);
    input.after.cases[0].taskRevision = 0;
    expect((await POST(request(input), context)).status).toBe(400);
  });
});
