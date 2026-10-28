import { describe, expect, it } from "vitest";
import { summarizeEvidenceCoverage, summarizeEvidenceControlCoverage, type SecurityEvidenceV1 } from "./evidence";

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

describe("required control coverage", () => {
  const expected = [
    { domain: "EMAIL" as const, controlId: "SPF" },
    { domain: "EMAIL" as const, controlId: "DMARC" },
  ];
  it("does not call a domain complete when only one of two controls is observed", () => {
    expect(summarizeEvidenceControlCoverage([
      { ...observed("EMAIL"), controlId: "SPF" },
    ], expected)).toEqual({
      coverage: "PARTIAL", assessedCount: 1, expectedCount: 2,
      missingControls: [{ domain: "EMAIL", controlId: "DMARC" }],
    });
  });
  it("never counts declarations or errors as observed", () => {
    expect(summarizeEvidenceControlCoverage([
      { ...observed("EMAIL"), controlId: "SPF", state: "DECLARED" },
      { ...observed("EMAIL"), controlId: "DMARC", state: "ERROR" },
    ], expected).coverage).toBe("UNASSESSED");
  });
  it("deduplicates requirements and accepts only exact observed control IDs", () => {
    const result = summarizeEvidenceControlCoverage([
      { ...observed("EMAIL"), controlId: "SPF" },
      { ...observed("EMAIL"), controlId: "DMARC" },
    ], [...expected, expected[0]!]);
    expect(result).toEqual({
      coverage: "COMPLETE", assessedCount: 2, expectedCount: 2, missingControls: [],
    });
  });
  it("treats no expected controls as unassessed", () => {
    expect(summarizeEvidenceControlCoverage([observed("EMAIL")], []).coverage).toBe("UNASSESSED");
  });
});
