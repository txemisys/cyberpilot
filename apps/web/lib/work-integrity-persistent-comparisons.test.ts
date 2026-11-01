import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  page: vi.fn(), read: vi.fn(),
}));
vi.mock("./work-integrity-persistent-captures", () => ({
  pageStoredIntegrityCaptures: mocks.page,
  readStoredIntegrityCapture: mocks.read,
}));
import {
  compareLatestStoredIntegrityCaptures, compareStoredIntegrityCaptureIds,
} from "./work-integrity-persistent-comparisons";

const at = "2026-10-30T10:00:00.000Z";
const later = "2026-10-31T10:00:00.000Z";
function capture(time: string, source = "source-a", organizationId = "org-a",
  complete = true) {
  return { capturedAt: time, source, organizationId, complete, cases: [] };
}
function summary(id: string, time: string) {
  return {
    id, capturedAt: time, source: "source-a", complete: true,
    caseCount: 0, digest: "a".repeat(64), createdAt: time,
  };
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.read.mockImplementation(async (_org: string, id: string) =>
    id === "before-1" ? capture(at) : id === "after-1" ? capture(later) : null);
  mocks.page.mockResolvedValue({
    captures: [summary("after-1", later), summary("before-1", at)],
    hasMore: false, nextCursor: null,
  });
});

describe("persisted integrity comparisons", () => {
  it("rejects invalid or repeated IDs without reading", async () => {
    await expect(compareStoredIntegrityCaptureIds("", "before-1", "after-1"))
      .rejects.toThrow("authenticated organization");
    await expect(compareStoredIntegrityCaptureIds("org-a", "before-1", "before-1"))
      .rejects.toThrow("distinct captures");
    expect(mocks.read).not.toHaveBeenCalled();
  });
  it("requires both captures to exist", async () => {
    await expect(compareStoredIntegrityCaptureIds("org-a", "missing", "after-1"))
      .rejects.toThrow("not found");
  });
  it("refuses comparisons between different sources", async () => {
    mocks.read.mockResolvedValueOnce(capture(at, "source-a"));
    mocks.read.mockResolvedValueOnce(capture(later, "source-b"));
    await expect(compareStoredIntegrityCaptureIds("org-a", "before-1", "after-1"))
      .rejects.toThrow("Cross-source");
  });
  it("refuses reversed chronological comparisons", async () => {
    await expect(compareStoredIntegrityCaptureIds("org-a", "after-1", "before-1"))
      .rejects.toThrow("chronologically");
  });
  it("compares verified historical snapshots conservatively", async () => {
    const result = await compareStoredIntegrityCaptureIds("org-a", "before-1", "after-1");
    expect(result.organizationId).toBe("org-a");
    expect(result.beforeCapturedAt).toBe(at);
    expect(result.afterCapturedAt).toBe(later);
    expect(result.complete).toBe(true);
    expect(result.counts.NEW).toBe(0);
    expect(mocks.read).toHaveBeenCalledWith("org-a", "before-1");
    expect(mocks.read).toHaveBeenCalledWith("org-a", "after-1");
  });
  it("marks incomplete comparisons as incomplete", async () => {
    mocks.read.mockResolvedValueOnce(capture(at, "source-a", "org-a", false));
    mocks.read.mockResolvedValueOnce(capture(later));
    const result = await compareStoredIntegrityCaptureIds("org-a", "before-1", "after-1");
    expect(result.complete).toBe(false);
    expect(result.warnings.some(item => item.includes("Incomplete"))).toBe(true);
  });
  it("uses only the latest two records in the requested organization and source", async () => {
    const result = await compareLatestStoredIntegrityCaptures("org-a", "source-a");
    expect(result?.before.id).toBe("before-1");
    expect(result?.after.id).toBe("after-1");
    expect(result?.comparison.complete).toBe(true);
    expect(mocks.page).toHaveBeenCalledWith("org-a", 2, undefined, "source-a");
  });
  it("returns null when a source lacks historical comparison data", async () => {
    mocks.page.mockResolvedValueOnce({
      captures: [summary("after-1", later)], hasMore: false, nextCursor: null,
    });
    expect(await compareLatestStoredIntegrityCaptures("org-a", "source-a")).toBeNull();
    expect(mocks.read).not.toHaveBeenCalled();
  });
  it("rejects invalid organization and source before querying", async () => {
    await expect(compareLatestStoredIntegrityCaptures("", "source-a"))
      .rejects.toThrow("Authenticated");
    await expect(compareLatestStoredIntegrityCaptures("org-a", " "))
      .rejects.toThrow("Authenticated");
    expect(mocks.page).not.toHaveBeenCalled();
  });
});
