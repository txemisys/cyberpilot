import { describe, expect, it } from "vitest";
import { getPriorityNavigation } from "./priority-navigation";

const finding = { id: "finding-1", lastSeenAt: new Date("2026-10-01T00:00:00Z") };

describe("Top Action navigation", () => {
  it("links open findings to an active playbook", () => {
    const navigation = getPriorityNavigation("finding-1", [finding], [
      { id: "remediation-1", finding: { id: "finding-1", status: "OPEN" }, status: "PROPOSED" },
    ]);
    expect(navigation.href).toBe("#remediation-remediation-1");
    expect(navigation.source?.lastSeenAt).toEqual(finding.lastSeenAt);
  });

  it("does not point to verified, failed, or unrelated remediations", () => {
    const remediations = [
      { id: "closed", finding: { id: "finding-1", status: "RESOLVED" }, status: "APPROVED" },
      { id: "failed", finding: { id: "finding-1", status: "OPEN" }, status: "FAILED" },
      { id: "different", finding: { id: "finding-2", status: "OPEN" }, status: "PROPOSED" },
    ];
    expect(getPriorityNavigation("finding-1", [finding], remediations).href).toBe("#finding-finding-1");
    expect(getPriorityNavigation("missing", [finding], remediations).playbook).toBeUndefined();
  });
});
