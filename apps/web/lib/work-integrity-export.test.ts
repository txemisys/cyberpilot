import { describe, expect, it } from "vitest";
import {
  INTEGRITY_CSV_FIELDS,
  buildIntegrityTriage,
  csvField,
  csvLine,
  defaultIntegrityExportOptions,
  integrityExportMetadata,
  selectIntegrityRows,
  summarizeIntegrityReview,
  workIntegrityCsv,
  workIntegrityJson,
  type IntegrityExportSource,
  type IntegrityReviewRow,
} from "./work-integrity-export";
import type { IntegrityCode, IntegrityFinding } from "./work-integrity";

function signal(
  code: IntegrityCode,
  severity: IntegrityFinding["severity"],
  workItemId: string,
  resourceId = workItemId,
): IntegrityFinding {
  return {
    code, severity, workItemId, resourceId,
    message: `Reason: ${code}`,
    recommendation: "Review the source record before making changes.",
  };
}
function source(): IntegrityExportSource {
  return {
    generatedAt: "2026-10-31T12:00:00.000Z",
    organizationId: "organization_one",
    checked: 4,
    nextCursor: "2026-10-01T12:00:00.000Z.work_00004",
    limitations: [
      "Read-only diagnostic; not verification.",
      "Mutable cursor when concurrent edits occur.",
    ],
    items: [
      {
        workItemId: "work_00001",
        status: "BLOCKED",
        revision: 3,
        updatedAt: new Date("2026-10-30T12:00:00.000Z"),
        complete: true,
        findings: [
          signal("FINDING_MISMATCH", "critical", "work_00001"),
          signal("ASSIGNEE_NOT_MEMBER", "attention", "work_00001"),
          signal("EVENT_REVISION_AHEAD", "critical", "work_00001", "event_00001"),
        ],
      },
      {
        workItemId: "work_00002",
        status: "IN_PROGRESS",
        revision: 1,
        updatedAt: "2026-10-28T12:00:00.000Z",
        complete: false,
        findings: [
          signal("HANDOFF_EXPIRED_PENDING", "attention", "work_00002", "handoff_00001"),
          signal("DEADLINE_BEFORE_CREATION", "info", "work_00002"),
        ],
      },
      {
        workItemId: "work_00003",
        status: "TODO",
        revision: 1,
        updatedAt: "2026-10-27T12:00:00.000Z",
        complete: true,
        findings: [],
      },
      {
        workItemId: "work_00004",
        status: "DONE",
        revision: 2,
        updatedAt: "2026-10-01T12:00:00.000Z",
        complete: true,
        findings: [signal("CHECKLIST_COMPLETED_WITHOUT_ACTOR", "info", "work_00004")],
      },
    ],
  };
}
function rows() {
  return selectIntegrityRows(source());
}
describe("integrity review export", () => {
  it("defaults to exporting all diagnostic findings without artificial empty rows", () => {
    expect(rows()).toHaveLength(6);
    expect(rows().every(row => row.code !== "")).toBe(true);
  });
  it("preserves source work, resource and diagnostic identifiers", () => {
    const exported = rows().find(row => row.code === "EVENT_REVISION_AHEAD")!;
    expect(exported.workItemId).toBe("work_00001");
    expect(exported.resourceId).toBe("event_00001");
    expect(exported.taskRevision).toBe(3);
  });
  it("preserves explicit per-record coverage", () => {
    expect(rows().filter(row => row.workItemId === "work_00002")
      .every(row => !row.coverageComplete)).toBe(true);
    expect(rows().filter(row => row.workItemId === "work_00001")
      .every(row => row.coverageComplete)).toBe(true);
  });
  it("does not mutate original review on export", () => {
    const original = source();
    const before = JSON.stringify(original);
    selectIntegrityRows(original);
    expect(JSON.stringify(original)).toBe(before);
  });
  it("normalizes Date and string timestamps to the same UTC representation", () => {
    const exported = rows();
    expect(exported.find(row => row.workItemId === "work_00001")?.taskUpdatedAt)
      .toBe("2026-10-30T12:00:00.000Z");
    expect(exported.find(row => row.workItemId === "work_00002")?.taskUpdatedAt)
      .toBe("2026-10-28T12:00:00.000Z");
  });
  it.each(["critical", "attention", "info"] as const)(
    "selects only %s findings",
    severity => {
      const selected = selectIntegrityRows(source(), {
        ...defaultIntegrityExportOptions, severity,
      });
      expect(selected.length).toBeGreaterThan(0);
      expect(selected.every(row => row.severity === severity)).toBe(true);
    },
  );
  it("does not exclude other severity values with all filter", () => {
    expect(selectIntegrityRows(source(), defaultIntegrityExportOptions)).toHaveLength(6);
  });
  it("filters by exact diagnostic codes", () => {
    const selected = selectIntegrityRows(source(), {
      ...defaultIntegrityExportOptions,
      codes: new Set(["FINDING_MISMATCH", "HANDOFF_EXPIRED_PENDING"]),
    });
    expect(selected.map(row => row.code)).toEqual([
      "FINDING_MISMATCH", "HANDOFF_EXPIRED_PENDING",
    ]);
  });
  it("returns no findings for empty code selector", () => {
    expect(selectIntegrityRows(source(), {
      ...defaultIntegrityExportOptions, codes: new Set(),
    })).toEqual([]);
  });
  it("supports code and severity filtering together", () => {
    const selected = selectIntegrityRows(source(), {
      ...defaultIntegrityExportOptions,
      severity: "critical",
      codes: new Set(["ASSIGNEE_NOT_MEMBER", "FINDING_MISMATCH"]),
    });
    expect(selected.map(row => row.code)).toEqual(["FINDING_MISMATCH"]);
  });
  it("can include an explicit empty diagnostic row", () => {
    const selected = selectIntegrityRows(source(), {
      ...defaultIntegrityExportOptions, includeEmpty: true,
    });
    const empty = selected.find(row => row.workItemId === "work_00003");
    expect(empty?.code).toBe("");
    expect(empty?.message).toContain("No matching diagnostic");
    expect(empty?.recommendation).toContain("Do not treat");
  });
  it("marks empty diagnostic row with incomplete linked-record coverage", () => {
    const selected = selectIntegrityRows(source(), {
      ...defaultIntegrityExportOptions,
      includeEmpty: true,
      codes: new Set(["FINDING_MISMATCH"]),
    });
    const row = selected.find(item => item.workItemId === "work_00002");
    expect(row?.coverageComplete).toBe(false);
    expect(row?.message).toContain("truncated");
  });
  it("does not attribute any review decision to a human", () => {
    for (const row of rows()) {
      expect(row.disposition).toBe("unreviewed");
      expect(row.reviewerNote).toBe("");
    }
  });
  it("reports page limits in export metadata", () => {
    const metadata = integrityExportMetadata(source(), rows());
    expect(metadata.sourceHasMorePages).toBe(true);
    expect(metadata.recordsExamined).toBe(4);
    expect(metadata.recordsWithPartialCoverage).toBe(1);
    expect(metadata.findingsExported).toBe(6);
    expect(metadata.disclaimer).toContain("not an assurance");
  });
  it("does not count optional empty rows as findings", () => {
    const selected = selectIntegrityRows(source(), {
      ...defaultIntegrityExportOptions, includeEmpty: true,
    });
    expect(integrityExportMetadata(source(), selected).findingsExported).toBe(6);
  });
  it("marks the final page as having no continuation", () => {
    const input = source();
    input.nextCursor = null;
    expect(integrityExportMetadata(input, rows()).sourceHasMorePages).toBe(false);
  });
  it("preserves limitations rather than silently omitting them", () => {
    expect(integrityExportMetadata(source(), rows()).limitations).toEqual(source().limitations);
  });
});
describe("spreadsheet-safe CSV", () => {
  it("quotes every field", () => {
    expect(csvLine(["abc", 3, true, null])).toBe('"abc","3","true",""');
  });
  it("escapes double quotes", () => {
    expect(csvField('a"b')).toBe('"a""b"');
  });
  it("preserves commas and newlines within quotes", () => {
    expect(csvField("one,two\nthree")).toBe('"one,two\nthree"');
  });
  it.each([
    "=SUM(1,1)",
    "+SUM(1,1)",
    "-1+2",
    "@cmd",
    "  =HYPERLINK(\"https://invalid.example\")",
    "\t=cmd",
    "\r\n+formula",
  ])("neutralizes spreadsheet formula input %s", value => {
    expect(csvField(value).startsWith('"\'')).toBe(true);
  });
  it.each(["normal", "alpha@example.org", "123", "some-text", "https://example.org"])(
    "does not alter normal CSV values %s",
    value => expect(csvField(value)).toBe(`"${value}"`),
  );
  it("starts with BOM and uses consistent CRLF", () => {
    const csv = workIntegrityCsv(source(), rows());
    expect(csv.startsWith("\uFEFF")).toBe(true);
    expect(csv.endsWith("\r\n")).toBe(true);
    expect(csv.replaceAll("\r\n", "")).not.toContain("\n");
  });
  it("always includes every diagnostic export column", () => {
    const csv = workIntegrityCsv(source(), rows());
    for (const field of INTEGRITY_CSV_FIELDS)
      expect(csv).toContain(csvField(field));
  });
  it("writes metadata into an annotated export", () => {
    const csv = workIntegrityCsv(source(), rows());
    expect(csv).toContain('"Export type"');
    expect(csv).toContain('"More pages available","true"');
    expect(csv).toContain('"Incomplete linked-record coverage","1"');
    expect(csv).toContain('"Limitation","Read-only diagnostic; not verification."');
  });
  it("omits metadata when explicitly requested", () => {
    const csv = workIntegrityCsv(source(), rows(), false);
    expect(csv).not.toContain('"Export type"');
    expect(csv).toContain(csvField(INTEGRITY_CSV_FIELDS[0]));
  });
  it("escapes untrusted finding messages", () => {
    const input = source();
    input.items[0]!.findings[0]!.message = '=HYPERLINK("http://invalid")';
    const csv = workIntegrityCsv(input, selectIntegrityRows(input));
    expect(csv).toContain('"\'=HYPERLINK(');
  });
  it("escapes untrusted recommendation text", () => {
    const input = source();
    input.items[0]!.findings[0]!.recommendation = '  +EXEC("test")';
    const csv = workIntegrityCsv(input, selectIntegrityRows(input));
    expect(csv).toContain('"\'  +EXEC(');
  });
  it("escapes attacker-controlled linked identifiers", () => {
    const input = source();
    input.items[0]!.findings[0]!.resourceId = "=EXPLOIT()";
    expect(workIntegrityCsv(input, selectIntegrityRows(input))).toContain('"\'=EXPLOIT()"');
  });
  it("returns a safe header-only export for no findings", () => {
    const input = source();
    input.items = [];
    input.checked = 0;
    const csv = workIntegrityCsv(input, []);
    expect(csv).toContain(csvField(INTEGRITY_CSV_FIELDS[0]));
    expect(csv).toContain('"Diagnostic findings exported","0"');
  });
});
describe("structured JSON portability", () => {
  it("round trips record-level source properties", () => {
    const output = JSON.parse(workIntegrityJson(source(), rows()));
    expect(output.metadata.kind).toBe("CYBERPILOT_OPERATIONAL_INTEGRITY_REVIEW");
    expect(output.metadata.schemaVersion).toBe(1);
    expect(output.records).toHaveLength(6);
    expect(output.records[0].taskStatus).toBe("BLOCKED");
  });
  it("includes an explicit scope and generation timestamp", () => {
    const output = JSON.parse(workIntegrityJson(source(), rows()));
    expect(output.metadata.organizationId).toBe("organization_one");
    expect(output.metadata.generatedAt).toBe("2026-10-31T12:00:00.000Z");
  });
  it("has a portable empty review payload", () => {
    const output = JSON.parse(workIntegrityJson(source(), []));
    expect(output.records).toEqual([]);
    expect(output.metadata.findingsExported).toBe(0);
  });
});
describe("diagnostic statistics", () => {
  it("counts records and findings separately", () => {
    const stats = summarizeIntegrityReview(source());
    expect(stats.examined).toBe(4);
    expect(stats.withFindings).toBe(3);
    expect(stats.withoutFindings).toBe(1);
  });
  it("counts severity at diagnostic level", () => {
    const stats = summarizeIntegrityReview(source());
    expect(stats.critical).toBe(2);
    expect(stats.attention).toBe(2);
    expect(stats.informational).toBe(2);
  });
  it("counts incomplete coverage at task level", () => {
    expect(summarizeIntegrityReview(source()).partialCoverage).toBe(1);
  });
  it("sorts per-code totals by frequency and then name", () => {
    const stats = summarizeIntegrityReview(source());
    expect(stats.byCode.map(row => row.code)).toEqual(
      [...stats.byCode.map(row => row.code)].sort(),
    );
  });
  it("groups flagged tasks by status", () => {
    const stats = summarizeIntegrityReview(source());
    expect(stats.byStatus).toEqual([
      { status: "BLOCKED", checked: 1, flagged: 1 },
      { status: "DONE", checked: 1, flagged: 1 },
      { status: "IN_PROGRESS", checked: 1, flagged: 1 },
      { status: "TODO", checked: 1, flagged: 0 },
    ]);
  });
  it("works for empty pages without division by zero", () => {
    const input = source();
    input.items = [];
    expect(summarizeIntegrityReview(input)).toMatchObject({
      examined: 0, critical: 0, attention: 0, informational: 0,
      byCode: [], byStatus: [],
    });
  });
});
describe("actionable triage", () => {
  it("puts tenant boundaries before operational hygiene", () => {
    const triage = buildIntegrityTriage(rows());
    expect(triage[0]?.priority).toBe(1);
    expect(triage[0]?.title).toContain("Tenant");
  });
  it("groups repeated work items only once per workstream", () => {
    const repeated = [...rows(), rows()[0]!];
    const triage = buildIntegrityTriage(repeated);
    const relationGroup = triage.find(group => group.priority === 1)!;
    expect(relationGroup.affectedWorkItems).toEqual(["work_00001"]);
    expect(relationGroup.findingCount).toBe(2);
  });
  it("preserves source diagnostic codes in workstreams", () => {
    const groups = buildIntegrityTriage(rows());
    const allCodes = groups.flatMap(group => group.codes);
    expect(allCodes).toContain("FINDING_MISMATCH");
    expect(allCodes).toContain("EVENT_REVISION_AHEAD");
    expect(allCodes).toContain("HANDOFF_EXPIRED_PENDING");
  });
  it("includes a human next action and explicit verification caveat", () => {
    const groups = buildIntegrityTriage(rows());
    for (const group of groups) {
      expect(group.nextAction.length).toBeGreaterThan(40);
      expect(group.verificationCaveat).toContain("not proven");
    }
  });
  it("does not produce irrelevant triage for no diagnostic signals", () => {
    expect(buildIntegrityTriage([])).toEqual([]);
  });
  it("does not mistake an empty-match row for a real diagnostic", () => {
    const empty = selectIntegrityRows(source(), {
      ...defaultIntegrityExportOptions,
      includeEmpty: true,
      codes: new Set(),
    });
    expect(buildIntegrityTriage(empty)).toEqual([]);
  });
  it("does not modify review disposition through triage", () => {
    const selected: IntegrityReviewRow[] = rows();
    const before = JSON.stringify(selected);
    buildIntegrityTriage(selected);
    expect(JSON.stringify(selected)).toBe(before);
  });
});
