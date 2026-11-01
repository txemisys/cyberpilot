import { beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  read: vi.fn(), workFind: vi.fn(), auditCreate: vi.fn(), auditFind: vi.fn(),
}));
vi.mock("@cyberpilot/database", () => ({
  db: {
    remediationWorkItem: { findFirst: mocks.workFind },
    auditEvent: { create: mocks.auditCreate, findMany: mocks.auditFind },
  },
}));
vi.mock("./work-integrity-persistent-captures", () => ({
  readStoredIntegrityCapture: mocks.read,
}));
import {
  linkIntegrityCaseToWork, listIntegrityWorkLinks, parseIntegrityWorkLinkInput,
  INTEGRITY_WORK_LINK_ACTION,
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
      { id: "audit-123", resourceId: "work-456",
        actorUserId: "user-123", occurredAt: new Date("2026-11-01T10:00:00.000Z"),
        metadata: { captureId: "capture-123", caseKey } },
      { id: "audit-456", resourceId: "work-789",
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
});
