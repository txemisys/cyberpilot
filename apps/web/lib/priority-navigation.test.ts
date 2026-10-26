import { describe, expect, it } from "vitest";
import { getPriorityNavigation } from "./priority-navigation";

const finding = { id: "finding-1", lastSeenAt: new Date("2026-10-01T00:00:00Z") };

describe("Top Action navigation", () => {
  it("links open findings to an active playbook", () => {
    const navigation = getPriorityNavigation("finding-1", [finding], [
      { id: "remediation-1", finding: { id: "finding-1", status: "OPEN" }, status: "PROPOSED", createdAt: new Date("2026-10-01") },
    ]);
    expect(navigation.href).toBe("#remediation-remediation-1");
    expect(navigation.source?.lastSeenAt).toEqual(finding.lastSeenAt);
  });

  it("does not point to verified, failed, or unrelated remediations", () => {
    const remediations = [
      { id: "closed", finding: { id: "finding-1", status: "RESOLVED" }, status: "APPROVED", createdAt: new Date("2026-10-01") },
      { id: "failed", finding: { id: "finding-1", status: "OPEN" }, status: "FAILED", createdAt: new Date("2026-10-01") },
      { id: "different", finding: { id: "finding-2", status: "OPEN" }, status: "PROPOSED", createdAt: new Date("2026-10-01") },
    ];
    expect(getPriorityNavigation("finding-1", [finding], remediations).href).toBe("#finding-finding-1");
    expect(getPriorityNavigation("missing", [finding], remediations).playbook).toBeUndefined();
  });
  it("selects execution over approval and proposal regardless of ordering", () => {
    const choices = [
      { id: "proposed", finding: { id: finding.id, status: "OPEN", createdAt: new Date("2026-10-01") }, status: "PROPOSED", createdAt: new Date("2026-10-20") },
      { id: "executing", finding: { id: finding.id, status: "OPEN", createdAt: new Date("2026-10-01") }, status: "EXECUTING", createdAt: new Date("2026-10-01") },
      { id: "approved", finding: { id: finding.id, status: "OPEN", createdAt: new Date("2026-10-01") }, status: "APPROVED", createdAt: new Date("2026-10-15") },
    ];
    expect(getPriorityNavigation(finding.id, [finding], choices).href).toBe("#remediation-executing");
    expect(getPriorityNavigation(finding.id, [finding], choices.reverse()).href).toBe("#remediation-executing");
  });
});
