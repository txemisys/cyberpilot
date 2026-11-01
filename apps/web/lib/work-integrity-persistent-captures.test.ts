import { beforeEach, describe, expect, it, vi } from "vitest";

const mock = vi.hoisted(() => ({
  findMany: vi.fn(),
  findFirst: vi.fn(),
  create: vi.fn(),
  auditCreate: vi.fn(),
  transaction: vi.fn(),
}));
vi.mock("@cyberpilot/database", () => ({
  db: {
    integrityCaseCapture: {
      findMany: mock.findMany,
      findFirst: mock.findFirst,
    },
    $transaction: mock.transaction,
  },
}));
import {
  DEFAULT_CAPTURE_POLICY, ingestStoredIntegrityCaptures,
  listStoredIntegrityCaptures, readStoredIntegrityCapture,
  pageStoredIntegrityCaptures, decodeCaptureHistoryCursor,
} from "./work-integrity-persistent-captures";

const scope = { organizationId: "org-1", actorUserId: "user-1" };
const at = "2026-10-31T10:00:00.000Z";
function capture(organizationId = "org-1", source = "test-source") {
  return {
    organizationId, source, capturedAt: at, complete: true, cases: [],
  };
}
function row() {
  return {
    id: "capture-1", source: "test-source", capturedAt: new Date(at),
    complete: true, caseCount: 0, digest: "a".repeat(64),
    createdAt: new Date(at),
  };
}
beforeEach(() => {
  vi.resetAllMocks();
  mock.findMany.mockResolvedValue([]);
  mock.transaction.mockImplementation(async (fn: (tx: unknown) => unknown) => fn({
    integrityCaseCapture: {
      findMany: mock.findMany,
      create: mock.create,
    },
    auditEvent: { create: mock.auditCreate },
  }));
  mock.create.mockResolvedValue(row());
  mock.auditCreate.mockResolvedValue({ id: "audit-1" });
});

describe("stored integrity capture isolation", () => {
  it("requires an organization for history", async () => {
    await expect(listStoredIntegrityCaptures("")).rejects.toThrow("Organization");
    expect(mock.findMany).not.toHaveBeenCalled();
  });
  it("rejects invalid history limits before querying", async () => {
    for (const limit of [0, -1, 1001, 1.5, Number.NaN])
      await expect(listStoredIntegrityCaptures("org-1", limit)).rejects.toThrow("limit");
    expect(mock.findMany).not.toHaveBeenCalled();
  });
  it("restricts history to the organization and maps dates", async () => {
    mock.findMany.mockResolvedValueOnce([row()]);
    const result = await listStoredIntegrityCaptures("org-1", 20);
    expect(mock.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { organizationId: "org-1" }, take: 20,
    }));
    expect(result).toEqual([{
      id: "capture-1", source: "test-source", capturedAt: at,
      complete: true, caseCount: 0, digest: "a".repeat(64),
      createdAt: at,
    }]);
  });
  it("enforces an exclusive timestamp cursor", async () => {
    await listStoredIntegrityCaptures("org-1", 10, new Date(at));
    expect(mock.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { organizationId: "org-1", capturedAt: { lt: new Date(at) } },
    }));
  });
  it("rejects malformed cursor dates", async () => {
    await expect(listStoredIntegrityCaptures("org-1", 10, new Date("invalid")))
      .rejects.toThrow("cursor");
  });
  it("reads payload only through tenant-filtered query", async () => {
    mock.findFirst.mockResolvedValueOnce(null);
    expect(await readStoredIntegrityCapture("org-1", "capture-1")).toBeNull();
    expect(mock.findFirst).toHaveBeenCalledWith(expect.objectContaining({
      where: { id: "capture-1", organizationId: "org-1" },
    }));
  });
  it("rejects cross-tenant persisted payload", async () => {
    mock.findFirst.mockResolvedValueOnce({
      payload: capture("other-org"), digest: "a".repeat(64),
    });
    await expect(readStoredIntegrityCapture("org-1", "capture-1"))
      .rejects.toThrow("tenant isolation");
  });
});

describe("transactional integrity ingestion", () => {
  it("requires an authenticated actor and tenant", async () => {
    await expect(ingestStoredIntegrityCaptures({
      organizationId: "", actorUserId: "user-1",
    }, [capture()])).rejects.toThrow("Authenticated");
    await expect(ingestStoredIntegrityCaptures({
      organizationId: "org-1", actorUserId: "",
    }, [capture()])).rejects.toThrow("Authenticated");
    expect(mock.transaction).not.toHaveBeenCalled();
  });
  it("rejects cross-organization captures before starting transaction", async () => {
    await expect(ingestStoredIntegrityCaptures(scope, [capture("other-org")]))
      .rejects.toThrow("Cross-organization");
    expect(mock.transaction).not.toHaveBeenCalled();
  });
  it("rejects empty and oversized batches before transaction", async () => {
    await expect(ingestStoredIntegrityCaptures(scope, [])).rejects.toThrow("batch size");
    await expect(ingestStoredIntegrityCaptures(scope,
      Array.from({ length: 101 }, () => capture())))
      .rejects.toThrow("batch size");
    expect(mock.transaction).not.toHaveBeenCalled();
  });
  it("persists accepted captures with tenant, actor and audit event", async () => {
    const result = await ingestStoredIntegrityCaptures(scope, [capture()]);
    expect(result.stored).toHaveLength(1);
    expect(result.plan.accepted).toBe(1);
    expect(mock.transaction).toHaveBeenCalledWith(
      expect.any(Function), expect.objectContaining({ isolationLevel: "Serializable" }),
    );
    expect(mock.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { organizationId: "org-1", source: { in: ["test-source"] } },
    }));
    expect(mock.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        organizationId: "org-1", createdById: "user-1",
        source: "test-source", complete: true, caseCount: 0,
      }),
    }));
    expect(mock.auditCreate).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        organizationId: "org-1", actorUserId: "user-1",
        action: "INTEGRITY_CAPTURES_INGESTED",
      }),
    }));
  });
  it("rejects conflicting identities atomically", async () => {
    mock.findMany.mockResolvedValueOnce([{ payload: {
      ...capture(), complete: false,
    } }]);
    await expect(ingestStoredIntegrityCaptures(scope, [capture()]))
      .rejects.toThrow("rejected by policy");
    expect(mock.create).not.toHaveBeenCalled();
    expect(mock.auditCreate).not.toHaveBeenCalled();
  });
  it("skips identical captures without creating an audit event", async () => {
    mock.findMany.mockResolvedValueOnce([{ payload: capture() }]);
    const result = await ingestStoredIntegrityCaptures(scope, [capture()]);
    expect(result.plan.skippedIdentical).toBe(1);
    expect(result.stored).toEqual([]);
    expect(mock.create).not.toHaveBeenCalled();
    expect(mock.auditCreate).not.toHaveBeenCalled();
  });
  it("rejects stale captures using policy", async () => {
    const policy = { ...DEFAULT_CAPTURE_POLICY, maxAgeDays: 1 };
    await expect(ingestStoredIntegrityCaptures(scope, [capture()], policy))
      .rejects.toThrow("rejected by policy");
    expect(mock.create).not.toHaveBeenCalled();
  });
  it("rolls back if audit persistence fails", async () => {
    mock.auditCreate.mockRejectedValueOnce(new Error("audit unavailable"));
    await expect(ingestStoredIntegrityCaptures(scope, [capture()]))
      .rejects.toThrow("audit unavailable");
    expect(mock.transaction).toHaveBeenCalled();
  });
});

describe("stable capture history pagination", () => {
  it("rejects malformed opaque cursors", () => {
    for (const cursor of ["", "bad=", "!", "YWJj", "e30"]) {
      expect(() => decodeCaptureHistoryCursor(cursor)).toThrow("cursor");
    }
  });
  it("enforces organization scope and bounded page sizes", async () => {
    await expect(pageStoredIntegrityCaptures("", 10)).rejects.toThrow("Organization");
    await expect(pageStoredIntegrityCaptures("org-1", 0)).rejects.toThrow("page size");
    await expect(pageStoredIntegrityCaptures("org-1", 101)).rejects.toThrow("page size");
    expect(mock.findMany).not.toHaveBeenCalled();
  });
  it("returns an opaque next cursor and source filter", async () => {
    const first = { ...row(), id: "capture-2" };
    const second = { ...row(), id: "capture-1" };
    mock.findMany.mockResolvedValueOnce([first, second]);
    const result = await pageStoredIntegrityCaptures("org-1", 1, undefined, "test-source");
    expect(result.captures).toHaveLength(1);
    expect(result.hasMore).toBe(true);
    expect(result.nextCursor).toBeTruthy();
    expect(decodeCaptureHistoryCursor(result.nextCursor!)).toEqual({
      capturedAt: at, id: "capture-2",
    });
    expect(mock.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { organizationId: "org-1", source: "test-source" },
      take: 2,
      orderBy: [{ capturedAt: "desc" }, { id: "desc" }],
    }));
  });
  it("uses an exclusive composite cursor to avoid skipping same-time captures", async () => {
    const cursor = Buffer.from(JSON.stringify({
      capturedAt: at, id: "capture-2",
    })).toString("base64url");
    mock.findMany.mockResolvedValueOnce([{ ...row(), id: "capture-1" }]);
    const result = await pageStoredIntegrityCaptures("org-1", 5, cursor);
    expect(result.hasMore).toBe(false);
    expect(result.nextCursor).toBeNull();
    expect(mock.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: {
        organizationId: "org-1",
        OR: [
          { capturedAt: { lt: new Date(at) } },
          { capturedAt: new Date(at), id: { lt: "capture-2" } },
        ],
      },
    }));
  });
  it("rejects empty source filters", async () => {
    await expect(pageStoredIntegrityCaptures("org-1", 10, undefined, " "))
      .rejects.toThrow("source");
  });
  it("does not expose another tenant's captures through the history query", async () => {
    mock.findMany.mockResolvedValueOnce([]);
    expect((await pageStoredIntegrityCaptures("org-2")).captures).toEqual([]);
    expect(mock.findMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { organizationId: "org-2" },
    }));
  });
});
