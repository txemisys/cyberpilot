import { describe, expect, it } from "vitest";
import { summarizeEvidenceCoverage, type SecurityEvidenceV1 } from "./evidence";

const observed = (domain: SecurityEvidenceV1["domain"]): SecurityEvidenceV1 => ({
  schemaVersion: 1,
  organizationId: "org-a",
  source: "LAB",
  domain,
  controlId: "TEST_CONTROL",
  state: "OBSERVED",
  observedAt: new Date("2026-10-28T10:00:00Z"),
  scope: "lab",
  details: {},
});

describe("provider-neutral evidence coverage", () => {
  it("never treats missing evidence or missing expected scope as complete", () => {
    expect(summarizeEvidenceCoverage([], ["IDENTITY", "BACKUP"]).coverage).toBe("UNASSESSED");
    expect(summarizeEvidenceCoverage([observed("WEB")], []).coverage).toBe("UNASSESSED");
  });

  it("keeps declared, unknown and errored evidence unassessed", () => {
    const evidence = ["DECLARED", "UNKNOWN", "ERROR"].map((state) => ({
      ...observed("BACKUP"),
      state: state as "DECLARED" | "UNKNOWN" | "ERROR",
    }));
    expect(summarizeEvidenceCoverage(evidence, ["BACKUP"]).coverage).toBe("UNASSESSED");
  });

  it("reports partial scope rather than a misleading complete posture", () => {
    expect(summarizeEvidenceCoverage([observed("EMAIL")], ["EMAIL", "BACKUP"])).toEqual({
      coverage: "PARTIAL",
      assessedDomains: ["EMAIL"],
      unassessedDomains: ["BACKUP"],
    });
  });

  it("reports complete only when every expected domain has observed, timestamped evidence", () => {
    const result = summarizeEvidenceCoverage(
      [observed("WEB"), observed("EMAIL"), { ...observed("BACKUP"), observedAt: null }],
      ["EMAIL", "WEB", "BACKUP", "WEB"],
    );
    expect(result.coverage).toBe("PARTIAL");
    expect(summarizeEvidenceCoverage([observed("WEB"), observed("EMAIL")], ["EMAIL", "WEB"]).coverage).toBe("COMPLETE");
  });
});
