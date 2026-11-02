import { beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  read: vi.fn(), workFind: vi.fn(), auditCreate: vi.fn(), auditFind: vi.fn(),
  transaction: vi.fn(), advisoryLock: vi.fn(),
}));
vi.mock("@cyberpilot/database", () => ({
  db: {
    remediationWorkItem: { findFirst: mocks.workFind },
    auditEvent: { create: mocks.auditCreate, findMany: mocks.auditFind },
    $transaction: mocks.transaction,
  },
}));
vi.mock("./work-integrity-persistent-captures", () => ({
  readStoredIntegrityCapture: mocks.read,
}));
import {
  linkIntegrityCaseToWork, listIntegrityWorkLinks, listIntegrityWorkLinkHistory,
  projectIntegrityLinkHistory, parseIntegrityWorkLinkInput,
  INTEGRITY_WORK_LINK_ACTION, unlinkIntegrityCaseFromWork,
  parseIntegrityWorkUnlinkInput, INTEGRITY_WORK_UNLINK_ACTION,
  listCompleteIntegrityWorkLinkState, listIntegrityWorkLinkHistoryPage,
} from "./work-integrity-evidence-links";

const caseKey = JSON.stringify(["work-123", "MISSING_EVIDENCE", "resource-1"]);
const input = { captureId: "capture-123", caseKey, workItemId: "work-456" };
const scope = { organizationId: "org-123", actorUserId: "user-123", role: "ADMIN" as const };
beforeEach(() => {
  vi.resetAllMocks();
  mocks.read.mockResolvedValue({
    organizationId: "org-123", source: "source-a",
    capturedAt: "2026-10-31T10:00:00.000Z", complete: true,
    cases: [{ key: caseKey, workItemId: "work-123",
      code: "MISSING_EVIDENCE", resourceId: "resource-1" }],
  });
  mocks.workFind.mockResolvedValue({ id: "work-456" });
  mocks.auditCreate.mockResolvedValue({
    id: "audit-123", occurredAt: new Date("2026-11-01T10:00:00.000Z"),
    actorUserId: "user-123",
  });
  mocks.auditFind.mockResolvedValue([]);
  mocks.transaction.mockImplementation(async (fn: (tx: unknown) => Promise<unknown>) => fn({
    auditEvent: { findFirst: mocks.auditFind, findMany: mocks.auditFind, create: mocks.auditCreate },
    $queryRaw: mocks.advisoryLock,
  }));
});

describe("diagnostic evidence to work associations", () => {
  it("rejects malformed and extra fields", () => {
    expect(() => parseIntegrityWorkLinkInput(null)).toThrow("object");
    expect(() => parseIntegrityWorkLinkInput({ ...input, status: "DONE" }))
      .toThrow("Unknown");
    expect(() => parseIntegrityWorkLinkInput({ ...input, caseKey: "" }))
      .toThrow("identity");
  });
  it("restricts writes to organization administrators", async () => {
    await expect(linkIntegrityCaseToWork({ ...scope, role: "MEMBER" }, input))
      .rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(mocks.read).not.toHaveBeenCalled();
  });
  it("requires a tenant-scoped, verified capture", async () => {
    mocks.read.mockResolvedValueOnce(null);
    await expect(linkIntegrityCaseToWork(scope, input))
      .rejects.toMatchObject({ code: "MISSING" });
    expect(mocks.workFind).not.toHaveBeenCalled();
  });
  it("requires the exact diagnostic case identity", async () => {
    await expect(linkIntegrityCaseToWork(scope, { ...input,
      caseKey: JSON.stringify(["work-123", "OTHER", "resource-1"]) }))
      .rejects.toMatchObject({ code: "MISSING" });
    expect(mocks.auditCreate).not.toHaveBeenCalled();
  });
  it("requires an existing work item in the same organization", async () => {
    mocks.workFind.mockResolvedValueOnce(null);
    await expect(linkIntegrityCaseToWork(scope, input))
      .rejects.toMatchObject({ code: "MISSING" });
    expect(mocks.workFind).toHaveBeenCalledWith({
      where: { id: "work-456", organizationId: "org-123" },
      select: { id: true },
    });
    expect(mocks.auditCreate).not.toHaveBeenCalled();
  });
  it("records a human-authored audit link without changing work status or security score", async () => {
    const result = await linkIntegrityCaseToWork(scope, input);
    expect(result).toMatchObject({ auditId: "audit-123", ...input });
    expect(mocks.auditCreate).toHaveBeenCalledWith({
      data: expect.objectContaining({
        organizationId: "org-123", actorUserId: "user-123",
        action: INTEGRITY_WORK_LINK_ACTION, resourceId: "work-456",
        metadata: expect.objectContaining({
          captureId: "capture-123", caseKey, workItemId: "work-456",
        }),
      }),
      select: { id: true, occurredAt: true, actorUserId: true },
    });
  });
  it("returns only associations matching the selected capture", async () => {
    mocks.auditFind.mockResolvedValueOnce([
      { id: "audit-123", action: INTEGRITY_WORK_LINK_ACTION, resourceId: "work-456",
        actorUserId: "user-123", occurredAt: new Date("2026-11-01T10:00:00.000Z"),
        metadata: { captureId: "capture-123", caseKey } },
      { id: "audit-456", action: INTEGRITY_WORK_LINK_ACTION, resourceId: "work-789",
        actorUserId: "user-123", occurredAt: new Date(),
        metadata: { captureId: "other-capture", caseKey } },
    ]);
    const links = await listIntegrityWorkLinks("org-123", "capture-123");
    expect(links).toHaveLength(1);
    expect(links[0]?.workItemId).toBe("work-456");
    expect(mocks.auditFind).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ organizationId: "org-123",
        metadata: { path: ["captureId"], equals: "capture-123" } }),
    }));
  });
  it("projects withdrawn links without erasing historical audit events", () => {
    const event = {
      auditId: "audit-123", originalAuditId: null, action: "LINK" as const,
      captureId: "capture-123", caseKey, workItemId: "work-456",
      actorUserId: "user-123", occurredAt: "2026-11-01T10:00:00.000Z",
    };
    const withdrawal = {
      ...event, auditId: "audit-456", originalAuditId: "audit-123",
      action: "UNLINK" as const,
    };
    const projected = projectIntegrityLinkHistory([withdrawal, event]);
    expect(projected.active).toHaveLength(0);
    expect(projected.withdrawn).toHaveLength(1);
    expect(projected.events).toHaveLength(2);
    expect(projectIntegrityLinkHistory([event]).active).toHaveLength(1);
  });
  it("returns withdrawal events and a bounded history completeness indicator", async () => {
    mocks.auditFind.mockResolvedValueOnce([
      { id: "audit-456", action: "INTEGRITY_CAPTURE_CASE_UNLINKED_FROM_WORK",
        resourceId: "work-456", actorUserId: "user-123",
        occurredAt: new Date("2026-11-01T11:00:00.000Z"),
        metadata: { captureId: "capture-123", caseKey, originalAuditId: "audit-123" } },
      { id: "audit-123", action: INTEGRITY_WORK_LINK_ACTION,
        resourceId: "work-456", actorUserId: "user-123",
        occurredAt: new Date("2026-11-01T10:00:00.000Z"),
        metadata: { captureId: "capture-123", caseKey } },
    ]);
    const history = await listIntegrityWorkLinkHistory("org-123", "capture-123");
    expect(history.active).toHaveLength(0);
    expect(history.withdrawn).toHaveLength(1);
    expect(history.events).toHaveLength(2);
    expect(history.truncated).toBe(false);
  });

  it("rejects malformed unlink requests before accessing the database", () => {
    expect(() => parseIntegrityWorkUnlinkInput({ auditId: "audit-123", status: "DONE" }))
      .toThrow("Only auditId");
    expect(() => parseIntegrityWorkUnlinkInput({ auditId: "bad" }))
      .toThrow("audit ID");
  });
  it("forbids evidence withdrawal by read-only users", async () => {
    await expect(unlinkIntegrityCaseFromWork(
      { ...scope, role: "AUDITOR" }, { auditId: "audit-123" },
    )).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(mocks.transaction).not.toHaveBeenCalled();
  });
  it("rejects a withdrawal for an unknown organization-scoped link", async () => {
    mocks.auditFind.mockResolvedValueOnce(null);
    await expect(unlinkIntegrityCaseFromWork(
      scope, { auditId: "audit-123" },
    )).rejects.toMatchObject({ code: "MISSING" });
    expect(mocks.auditCreate).not.toHaveBeenCalled();
    expect(mocks.auditFind).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ organizationId: "org-123",
        action: INTEGRITY_WORK_LINK_ACTION }),
    }));
  });
  it("prevents a second withdrawal of the same audit association", async () => {
    mocks.auditFind
      .mockResolvedValueOnce({ id: "audit-123", resourceId: "work-456",
        metadata: { captureId: "capture-123", caseKey } })
      .mockResolvedValueOnce({ id: "withdrawal-123" });
    await expect(unlinkIntegrityCaseFromWork(
      scope, { auditId: "audit-123" },
    )).rejects.toMatchObject({ code: "CONFLICT" });
    expect(mocks.auditCreate).not.toHaveBeenCalled();
  });
  it("records a separate immutable withdrawal event", async () => {
    mocks.auditFind
      .mockResolvedValueOnce({ id: "audit-123", resourceId: "work-456",
        metadata: { captureId: "capture-123", caseKey } })
      .mockResolvedValueOnce(null);
    mocks.auditCreate.mockResolvedValueOnce({ id: "withdrawal-123" });
    const result = await unlinkIntegrityCaseFromWork(
      scope, { auditId: "audit-123" },
    );
    expect(result).toEqual({ auditId: "withdrawal-123", originalAuditId: "audit-123" });
    expect(mocks.advisoryLock).toHaveBeenCalledTimes(1);
    expect(mocks.auditCreate).toHaveBeenCalledWith({
      data: expect.objectContaining({
        action: INTEGRITY_WORK_UNLINK_ACTION, organizationId: "org-123",
        resourceId: "work-456", metadata: expect.objectContaining({
          originalAuditId: "audit-123", captureId: "capture-123", caseKey,
        }),
      }),
      select: { id: true },
    });
    expect(mocks.transaction).toHaveBeenCalledWith(
      expect.any(Function), { isolationLevel: "ReadCommitted" },
    );
  });

  it("reports a truncated capture-specific audit history at the read boundary", async () => {
    const row = {
      id: "audit-123", action: INTEGRITY_WORK_LINK_ACTION,
      resourceId: "work-456", actorUserId: "user-123",
      occurredAt: new Date("2026-11-01T10:00:00.000Z"),
      metadata: { captureId: "capture-123", caseKey },
    };
    mocks.auditFind.mockResolvedValueOnce(Array.from({ length: 1000 }, () => row));
    const history = await listIntegrityWorkLinkHistory("org-123", "capture-123");
    expect(history.truncated).toBe(false);
    expect(mocks.auditFind).toHaveBeenCalledWith(expect.objectContaining({
      take: 1001,
      where: expect.objectContaining({
        metadata: { path: ["captureId"], equals: "capture-123" },
      }),
    }));
  });

  it("detects an actual overflow without exposing the lookahead event", async () => {
    const rows = Array.from({ length: 1001 }, (_, i) => ({
      id: `audit-${i}`, action: INTEGRITY_WORK_LINK_ACTION,
      resourceId: "work-456", actorUserId: "user-123",
      occurredAt: new Date("2026-11-01T10:00:00.000Z"),
      metadata: { captureId: "capture-123", caseKey },
    }));
    mocks.auditFind.mockResolvedValueOnce(rows);
    const history = await listIntegrityWorkLinkHistory("org-123", "capture-123");
    expect(history.truncated).toBe(true);
    expect(history.events).toHaveLength(1000);
    expect(history.events.some(event => event.auditId === "audit-1000")).toBe(false);
  });

  it("reconstructs a withdrawn link across distinct history pages", async () => {
    const row = (id: string, action: string, originalAuditId?: string) => ({
      id, action, resourceId: "work-456", actorUserId: "user-123",
      occurredAt: new Date("2026-11-01T10:00:00.000Z"),
      metadata: { captureId: "capture-123", caseKey, ...(originalAuditId ? { originalAuditId } : {}) },
    });
    const first = [
      row("withdrawal-123", INTEGRITY_WORK_UNLINK_ACTION, "audit-123"),
      ...Array.from({ length: 999 }, (_, i) => row(`filler-${i}`, INTEGRITY_WORK_LINK_ACTION)),
      row("lookahead", INTEGRITY_WORK_LINK_ACTION),
    ];
    const second = [row("audit-123", INTEGRITY_WORK_LINK_ACTION)];
    mocks.auditFind.mockResolvedValueOnce(first).mockResolvedValueOnce(second);
    const result = await listCompleteIntegrityWorkLinkState("org-123", "capture-123");
    expect(result.withdrawn.some(event => event.auditId === "audit-123")).toBe(true);
    expect(result.active.some(event => event.auditId === "audit-123")).toBe(false);
    expect(mocks.auditFind).toHaveBeenCalledTimes(2);
    expect(mocks.auditFind.mock.calls[1]?.[0]).toEqual(expect.objectContaining({
      where: expect.objectContaining({ organizationId: "org-123", OR: expect.any(Array) }),
    }));
  });
  it("rejects invalid page sizes before querying", async () => {
    await expect(listIntegrityWorkLinkHistoryPage("org-123", "capture-123", undefined, 1001))
      .rejects.toMatchObject({ code: "INVALID" });
    expect(mocks.auditFind).not.toHaveBeenCalled();
  });

  it("reconstructs active links under a repeatable-read database snapshot", async () => {
    const link = {
      id: "audit-123", action: INTEGRITY_WORK_LINK_ACTION,
      resourceId: "work-456", actorUserId: "user-123",
      occurredAt: new Date("2026-11-01T10:00:00.000Z"),
      metadata: { captureId: "capture-123", caseKey },
    };
    mocks.auditFind.mockResolvedValueOnce([link]);
    const result = await listCompleteIntegrityWorkLinkState("org-123", "capture-123");
    expect(result.active.map(item => item.auditId)).toEqual(["audit-123"]);
    expect(mocks.transaction).toHaveBeenCalledWith(
      expect.any(Function), { isolationLevel: "RepeatableRead" },
    );
  });

  it("keeps history cursor tenant scoped after advancing a page", async () => {
    mocks.auditFind.mockResolvedValueOnce([]);
    await listIntegrityWorkLinkHistoryPage(
      "tenant-b", "capture-123",
      { occurredAt: "2026-11-01T10:00:00.000Z", auditId: "audit-123" }, 25,
    );
    expect(mocks.auditFind).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({
        organizationId: "tenant-b",
        metadata: { path: ["captureId"], equals: "capture-123" },
        OR: [
          { occurredAt: { lt: new Date("2026-11-01T10:00:00.000Z") } },
          { occurredAt: new Date("2026-11-01T10:00:00.000Z"), id: { lt: "audit-123" } },
        ],
      }),
      take: 26,
    }));
  });

  it("does not accept a cursor with a malformed timestamp", async () => {
    await expect(listIntegrityWorkLinkHistoryPage(
      "org-123", "capture-123", { occurredAt: "not-a-date", auditId: "audit-123" },
    )).rejects.toMatchObject({ code: "INVALID" });
    expect(mocks.auditFind).not.toHaveBeenCalled();
  });

  it("does not accept a cursor with a malformed audit identifier", async () => {
    await expect(listIntegrityWorkLinkHistoryPage(
      "org-123", "capture-123",
      { occurredAt: "2026-11-01T10:00:00.000Z", auditId: "?" },
    )).rejects.toMatchObject({ code: "INVALID" });
    expect(mocks.auditFind).not.toHaveBeenCalled();
  });

  it("requires an organization for every paged history read", async () => {
    await expect(listIntegrityWorkLinkHistoryPage(
      "", "capture-123",
    )).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(mocks.auditFind).not.toHaveBeenCalled();
  });

  it("rejects fractional, negative and zero page sizes", async () => {
    for (const size of [0, -1, 1.5, NaN, Infinity]) {
      await expect(listIntegrityWorkLinkHistoryPage(
        "org-123", "capture-123", undefined, size,
      )).rejects.toMatchObject({ code: "INVALID" });
    }
    expect(mocks.auditFind).not.toHaveBeenCalled();
  });

  it("preserves chronological cursor when a row has invalid metadata", async () => {
    const rows = [
      { id: "audit-9", action: INTEGRITY_WORK_LINK_ACTION,
        resourceId: "work-456", actorUserId: "user-123",
        occurredAt: new Date("2026-11-01T12:00:00.000Z"),
        metadata: { captureId: "capture-123", caseKey } },
      { id: "audit-8", action: INTEGRITY_WORK_LINK_ACTION,
        resourceId: "work-456", actorUserId: "user-123",
        occurredAt: new Date("2026-11-01T11:00:00.000Z"),
        metadata: null },
    ];
    mocks.auditFind.mockResolvedValueOnce(rows);
    const page = await listIntegrityWorkLinkHistoryPage(
      "org-123", "capture-123", undefined, 1,
    );
    expect(page.events.map(event => event.auditId)).toEqual(["audit-9"]);
    expect(page.hasMore).toBe(true);
    expect(page.nextCursor).toEqual({
      occurredAt: "2026-11-01T12:00:00.000Z", auditId: "audit-9",
    });
  });

  it("fails closed if database pagination returns the same cursor twice", async () => {
    const row = {
      id: "audit-123", action: INTEGRITY_WORK_LINK_ACTION,
      resourceId: "work-456", actorUserId: "user-123",
      occurredAt: new Date("2026-11-01T10:00:00.000Z"),
      metadata: { captureId: "capture-123", caseKey },
    };
    mocks.auditFind.mockResolvedValue(Array.from({ length: 1001 }, () => row));
    await expect(listCompleteIntegrityWorkLinkState(
      "org-123", "capture-123",
    )).rejects.toMatchObject({ code: "INVALID" });
    expect(mocks.auditFind).toHaveBeenCalledTimes(2);
  });

  it("returns a complete state when the audit history is empty", async () => {
    const state = await listCompleteIntegrityWorkLinkState("org-123", "capture-123");
    expect(state).toEqual({ active: [], withdrawn: [], events: [] });
    expect(mocks.auditFind).toHaveBeenCalledTimes(1);
  });

  it("preserves independent links to the same work item after one withdrawal", () => {
    const base = {
      originalAuditId: null, action: "LINK" as const,
      captureId: "capture-123", caseKey, workItemId: "work-456",
      actorUserId: "user-123", occurredAt: "2026-11-01T10:00:00.000Z",
    };
    const state = projectIntegrityLinkHistory([
      { ...base, auditId: "withdrawal-1", originalAuditId: "link-1", action: "UNLINK" },
      { ...base, auditId: "link-2" },
      { ...base, auditId: "link-1" },
    ]);
    expect(state.active.map(item => item.auditId)).toEqual(["link-2"]);
    expect(state.withdrawn.map(item => item.auditId)).toEqual(["link-1"]);
    expect(state.events).toHaveLength(3);
  });

  it("does not let unrelated withdrawal IDs suppress an active link", () => {
    const base = {
      auditId: "link-1", originalAuditId: null, action: "LINK" as const,
      captureId: "capture-123", caseKey, workItemId: "work-456",
      actorUserId: "user-123", occurredAt: "2026-11-01T10:00:00.000Z",
    };
    const state = projectIntegrityLinkHistory([
      { ...base, auditId: "withdrawal-1", originalAuditId: "other-link", action: "UNLINK" },
      base,
    ]);
    expect(state.active.map(item => item.auditId)).toEqual(["link-1"]);
    expect(state.withdrawn).toHaveLength(0);
  });

  it("serializes concurrent withdrawals and rejects the second after the first commits", async () => {
    let releaseFirst!: () => void;
    let notifyFirst!: () => void;
    const firstLocked = new Promise<void>(resolve => { notifyFirst = resolve; });
    const firstMayCommit = new Promise<void>(resolve => { releaseFirst = resolve; });
    let firstHasLock = false;
    let withdrawn = false;
    let signalCommit!: () => void;
    const committed = new Promise<void>(resolve => { signalCommit = resolve; });
    mocks.transaction.mockImplementation(async (
      fn: (tx: unknown) => Promise<unknown>,
    ) => {
      const tx = {
        auditEvent: {
          findFirst: vi.fn(async (query: { where: { action: string } }) => {
            if (query.where.action === INTEGRITY_WORK_LINK_ACTION)
              return { id: "audit-123", resourceId: "work-456",
                metadata: { captureId: "capture-123", caseKey } };
            return withdrawn ? { id: "withdrawal-123" } : null;
          }),
          create: vi.fn(async () => {
            withdrawn = true;
            signalCommit();
            return { id: "withdrawal-123" };
          }),
        },
        $queryRaw: vi.fn(async () => {
          if (!firstHasLock) {
            firstHasLock = true;
            notifyFirst();
            await firstMayCommit;
          } else {
            await committed;
          }
          return [];
        }),
      };
      return fn(tx);
    });
    const first = unlinkIntegrityCaseFromWork(scope, { auditId: "audit-123" });
    await firstLocked;
    const second = unlinkIntegrityCaseFromWork(scope, { auditId: "audit-123" });
    releaseFirst();
    const results = await Promise.allSettled([first, second]);
    expect(results[0]).toMatchObject({
      status: "fulfilled",
      value: { originalAuditId: "audit-123" },
    });
    expect(results[1]).toMatchObject({
      status: "rejected", reason: { code: "CONFLICT" },
    });
  });

});
