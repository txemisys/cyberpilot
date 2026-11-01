import { beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  read: vi.fn(), workFind: vi.fn(), auditCreate: vi.fn(), auditFind: vi.fn(),
  transaction: vi.fn(),
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
    auditEvent: { findFirst: mocks.auditFind, create: mocks.auditCreate },
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
      where: expect.objectContaining({ organizationId: "org-123" }),
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
      expect.any(Function), { isolationLevel: "Serializable" },
    );
  });

});
