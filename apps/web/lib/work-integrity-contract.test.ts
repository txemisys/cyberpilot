import { describe, expect, it } from "vitest";
import {
  buildIntegrityTriage, csvLine, integrityExportMetadata,
  selectIntegrityRows, summarizeIntegrityReview, workIntegrityCsv,
  workIntegrityJson, type IntegrityExportSource,
} from "./work-integrity-export";
import type { IntegrityCode, IntegrityFinding } from "./work-integrity";

/**
 * End-to-end pure-data contract tests: diagnostics are produced by a scoped
 * read and are then transformed without dropping coverage and scope metadata.
 * These are deliberately offline; they do not claim a live database or tenant.
 */
const org = "organization_fixture";
function issue(workItemId: string, code: IntegrityCode, index: number): IntegrityFinding {
  return {
    workItemId, resourceId: `resource_${index}`, code,
    severity: code === "FINDING_MISMATCH" ? "critical" :
      code === "HANDOFF_EXPIRED_PENDING" ? "attention" : "info",
    message: `Observed discrepancy ${index}, possibly incomplete source`,
    recommendation: "Investigate the stored source; do not update control verification.",
  };
}
function fixture(size: number, page = 0): IntegrityExportSource {
  const items = Array.from({ length: size }, (_, index) => {
    const id = `work_${String(page * size + index + 1).padStart(6, "0")}`;
    return {
      workItemId: id,
      status: index % 3 === 0 ? "BLOCKED" : index % 3 === 1 ? "DONE" : "TODO",
      revision: index + 1,
      updatedAt: new Date(2026, 9, 31 - index % 20).toISOString(),
      complete: index % 4 !== 0,
      findings: index % 5 === 0 ? [] : [
        issue(id, index % 2 === 0 ? "FINDING_MISMATCH" :
          "HANDOFF_EXPIRED_PENDING", index),
      ],
    };
  });
  return {
    generatedAt: "2026-10-31T22:08:00.000Z",
    organizationId: org,
    checked: size,
    nextCursor: page < 2 ? `2026-10-01T00:00:00.000Z.work_${page}` : null,
    items,
    limitations: ["Only these records were loaded.", "No LIVE Microsoft 365 validation."],
  };
}
describe("portable review across bounded pages", () => {
  it.each([0, 1, 10, 25, 50, 100])("exports exactly %i scoped records", size => {
    const input = fixture(size);
    const selected = selectIntegrityRows(input, {
      includeEmpty: true, severity: "all", codes: null, includeExplanation: true,
    });
    expect(new Set(selected.map(row => row.workItemId)).size).toBe(size);
    expect(selected.length).toBe(size);
  });
  it("does not overcount items with multiple diagnostic signals", () => {
    const input = fixture(10);
    const first = input.items[1]!;
    first.findings.push(issue(first.workItemId, "DEADLINE_BEFORE_CREATION", 99));
    const stats = summarizeIntegrityReview(input);
    expect(stats.examined).toBe(10);
    expect(stats.withFindings).toBe(8);
    expect(stats.informational).toBeGreaterThan(0);
    expect(selectIntegrityRows(input).length).toBe(9);
  });
  it("makes the risk of cursor continuation explicit", () => {
    const first = fixture(25, 0);
    const last = fixture(25, 2);
    expect(integrityExportMetadata(first, selectIntegrityRows(first))
      .sourceHasMorePages).toBe(true);
    expect(integrityExportMetadata(last, selectIntegrityRows(last))
      .sourceHasMorePages).toBe(false);
  });
  it("does not merge unrelated pages into a false exhaustive assurance", () => {
    const pages = [fixture(25, 0), fixture(25, 1), fixture(25, 2)];
    const ids = pages.map(page =>
      new Set(selectIntegrityRows(page).map(row => row.workItemId)));
    expect([...ids[0]!].some(id => ids[1]!.has(id))).toBe(false);
    expect([...ids[1]!].some(id => ids[2]!.has(id))).toBe(false);
    expect(pages[0]!.nextCursor).not.toBeNull();
    expect(pages[1]!.nextCursor).not.toBeNull();
  });
  it("retains reviewer disposition as explicitly unreviewed on all pages", () => {
    for (const page of [fixture(10, 0), fixture(10, 1), fixture(10, 2)]) {
      expect(selectIntegrityRows(page).every(row =>
        row.disposition === "unreviewed" && row.reviewerNote === "")).toBe(true);
    }
  });
  it("never substitutes the task's DONE state for verified security", () => {
    const input = fixture(12);
    const completed = selectIntegrityRows(input).filter(row => row.taskStatus === "DONE");
    expect(completed.length).toBeGreaterThan(0);
    expect(completed.every(row => row.recommendation.includes("do not update control verification")))
      .toBe(true);
  });
  it("exposes source observation limits in CSV and JSON alike", () => {
    const input = fixture(12);
    const selected = selectIntegrityRows(input);
    const csv = workIntegrityCsv(input, selected);
    const json = workIntegrityJson(input, selected);
    expect(csv).toContain("No LIVE Microsoft 365 validation.");
    expect(json).toContain("No LIVE Microsoft 365 validation.");
    expect(csv).toContain('"Incomplete linked-record coverage","3"');
    expect(JSON.parse(json).metadata.recordsWithPartialCoverage).toBe(3);
  });
  it("maintains the scope boundary across all exported rows", () => {
    const first = fixture(17);
    const second = fixture(17, 1);
    second.organizationId = "organization_another";
    const a = JSON.parse(workIntegrityJson(first, selectIntegrityRows(first)));
    const b = JSON.parse(workIntegrityJson(second, selectIntegrityRows(second)));
    expect(a.metadata.organizationId).toBe(org);
    expect(b.metadata.organizationId).toBe("organization_another");
    expect(a.records.every((row: {workItemId: string}) =>
      !b.records.some((other: {workItemId: string}) => other.workItemId === row.workItemId))).toBe(true);
  });
  it("does not claim lack of findings is proof of completeness", () => {
    const input = fixture(1);
    const selected = selectIntegrityRows(input, {
      includeEmpty: true, severity: "all", codes: null, includeExplanation: true,
    });
    expect(selected[0]?.code).toBe("");
    expect(selected[0]?.coverageComplete).toBe(false);
    expect(selected[0]?.message).toContain("truncated");
  });
  it("keeps metadata on an empty page", () => {
    const empty = fixture(0);
    const csv = workIntegrityCsv(empty, []);
    const json = JSON.parse(workIntegrityJson(empty, []));
    expect(csv).toContain('"Records examined in page","0"');
    expect(json.metadata.recordsExamined).toBe(0);
    expect(json.metadata.findingsExported).toBe(0);
    expect(json.records).toEqual([]);
  });
  it("preserves the diagnostic's true linked resource id", () => {
    const input = fixture(8);
    const selected = selectIntegrityRows(input);
    expect(selected[0]?.resourceId).toBe("resource_1");
    expect(selected[0]?.workItemId).toBe("work_000002");
  });
  it("does not change source evidence after repeated exports", () => {
    const input = fixture(100);
    const before = JSON.stringify(input);
    const selected = selectIntegrityRows(input);
    workIntegrityCsv(input, selected);
    workIntegrityJson(input, selected);
    buildIntegrityTriage(selected);
    summarizeIntegrityReview(input);
    expect(JSON.stringify(input)).toBe(before);
  });
  it("deduplicates affected task identifiers per triage area", () => {
    const input = fixture(8);
    const selected = selectIntegrityRows(input);
    const duplicate = [selected[0]!, selected[0]!];
    const groups = buildIntegrityTriage([...selected, ...duplicate]);
    for (const group of groups) {
      expect(new Set(group.affectedWorkItems).size)
        .toBe(group.affectedWorkItems.length);
    }
  });
  it("sanitizes arbitrary spreadsheet formula fields in a full CSV row", () => {
    const fields = [
      "=2+2", " +CMD", "\t@script", "-44", "safe",
      '"=1+2', "@HYPERLINK", "\n=problem",
    ];
    const output = csvLine(fields);
    for (const field of fields.filter(value => /^[\s]*[=+@-]/.test(value))) {
      expect(output).toContain("'"+field);
    }
    expect(output).toContain('"safe"');
  });
  it("reports ordered, non-empty remediation guidance for detected problems", () => {
    const groups = buildIntegrityTriage(selectIntegrityRows(fixture(100)));
    expect(groups.length).toBeGreaterThan(0);
    expect(groups.map(group => group.priority)).toEqual(
      [...groups.map(group => group.priority)].sort((a,b) => a-b));
    expect(groups.every(group => group.nextAction.length > 30)).toBe(true);
  });
});
