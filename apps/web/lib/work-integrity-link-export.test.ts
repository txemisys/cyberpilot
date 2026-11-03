import { describe, expect, it } from "vitest";
import {
  buildIntegrityLinkExport, escapeIntegrityCsvCell, parseIntegrityLinkExportOptions,
} from "./work-integrity-link-export";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
function link(id: string, caseKey = "case-1"): IntegrityLinkHistoryEvent {
  return {
    auditId: id, originalAuditId: null, action: "LINK",
    captureId: "capture-1", caseKey, workItemId: "work-1",
    actorUserId: "user-1", occurredAt: "2026-11-01T10:00:00.000Z",
  };
}
function unlink(id: string, originalAuditId: string): IntegrityLinkHistoryEvent {
  return {
    ...link(id), action: "UNLINK", originalAuditId,
    occurredAt: "2026-11-02T10:00:00.000Z",
  };
}
describe("integrity link export", () => {
  it("defaults to CSV event export", () => {
    expect(parseIntegrityLinkExportOptions({})).toMatchObject({
      format: "csv", kind: "events", maxRows: 10000,
    });
  });
  it("escapes commas, quotes and newlines in CSV", () => {
    expect(escapeIntegrityCsvCell('one,"two"')).toBe('"one,""two"""');
    expect(escapeIntegrityCsvCell("line\nnext")).toBe('"line\nnext"');
    expect(escapeIntegrityCsvCell(null)).toBe("");
    expect(escapeIntegrityCsvCell(42)).toBe("42");
  });
  it.each(["=", "+", "-", "@"])("protects spreadsheet formulas prefixed by %s", prefix => {
    expect(escapeIntegrityCsvCell(prefix + "SUM(A1)")).toBe("'" + prefix + "SUM(A1)");
    expect(escapeIntegrityCsvCell("  " + prefix + "SUM(A1)"))
      .toBe("'  " + prefix + "SUM(A1)");
  });
  it("renders a CSV header and all historical events", () => {
    const result = buildIntegrityLinkExport(
      [link("link-1"), unlink("withdrawal-1", "link-1")],
      parseIntegrityLinkExportOptions({}), "capture-1",
    );
    expect(result.contentType).toContain("text/csv");
    expect(result.filename).toBe("integrity-links-capture-1-events.csv");
    expect(result.rows).toBe(2);
    expect(result.truncated).toBe(false);
    expect(result.content).toContain("originalAuditId,action,captureId");
    expect(result.content).toContain("withdrawal-1,link-1,UNLINK");
  });
  it("renders JSONL with one event per line", () => {
    const result = buildIntegrityLinkExport(
      [link("link-1"), link("link-2")],
      parseIntegrityLinkExportOptions({ format: "jsonl" }), "capture-1",
    );
    expect(result.contentType).toContain("application/x-ndjson");
    const rows = result.content.trim().split("\n").map(row => JSON.parse(row));
    expect(rows.map(row => row.auditId)).toEqual(["link-2", "link-1"]);
  });
  it("renders versioned JSON with row counts", () => {
    const result = buildIntegrityLinkExport(
      [link("link-1"), link("link-2")],
      parseIntegrityLinkExportOptions({ format: "json", maxRows: 1 }), "capture-1",
    );
    const json = JSON.parse(result.content);
    expect(json).toMatchObject({
      schemaVersion: 1, captureId: "capture-1",
      exportedRows: 1, totalRows: 2, truncated: true,
    });
    expect(json.rows).toHaveLength(1);
    expect(result.truncated).toBe(true);
  });
  it("exports case summaries without losing withdrawal counts", () => {
    const result = buildIntegrityLinkExport(
      [link("link-1"), unlink("withdrawal-1", "link-1")],
      parseIntegrityLinkExportOptions({ kind: "cases", format: "json" }), "capture-1",
    );
    const row = JSON.parse(result.content).rows[0];
    expect(row).toMatchObject({
      caseKey: "case-1", totalLinks: 1, activeLinks: 0, withdrawnLinks: 1,
    });
  });
  it("exports work summaries with their associated case keys", () => {
    const result = buildIntegrityLinkExport(
      [link("link-1", "case-1"), link("link-2", "case-2")],
      parseIntegrityLinkExportOptions({ kind: "work", format: "json" }), "capture-1",
    );
    const row = JSON.parse(result.content).rows[0];
    expect(row.caseKeys).toBe("case-1;case-2");
    expect(row.totalLinks).toBe(2);
  });
  it("exports actors and days separately", () => {
    const events = [link("link-1"), unlink("withdrawal-1", "link-1")];
    const actors = buildIntegrityLinkExport(
      events, parseIntegrityLinkExportOptions({ kind: "actors", format: "json" }),
      "capture-1",
    );
    const days = buildIntegrityLinkExport(
      events, parseIntegrityLinkExportOptions({ kind: "days", format: "json" }),
      "capture-1",
    );
    expect(JSON.parse(actors.content).rows[0].linksCreated).toBe(1);
    expect(JSON.parse(days.content).rows).toHaveLength(2);
  });
  it("filters exported events by exact diagnostic case identity", () => {
    const result = buildIntegrityLinkExport(
      [link("link-1", "case-1"), link("link-2", "case-2")],
      parseIntegrityLinkExportOptions({ caseKey: "case-2", format: "json" }),
      "capture-1",
    );
    expect(JSON.parse(result.content).rows.map((row: { auditId: string }) => row.auditId))
      .toEqual(["link-2"]);
  });
  it.each(["cases", "work", "actors", "days"] as const)(
    "applies case filters to %s aggregate exports", kind => {
      const result = buildIntegrityLinkExport(
        [link("link-1", "case-1"), link("link-2", "case-2")],
        parseIntegrityLinkExportOptions({ kind, format: "json", caseKey: "case-2" }),
        "capture-1",
      );
      const rows = JSON.parse(result.content).rows;
      expect(rows).toHaveLength(1);
      if (kind === "cases") expect(rows[0].caseKey).toBe("case-2");
      if (kind === "work") expect(rows[0].totalLinks).toBe(1);
      if (kind === "actors") expect(rows[0].linksCreated).toBe(1);
      if (kind === "days") expect(rows[0].linksCreated).toBe(1);
    },
  );
  it("produces a header-only CSV for empty history", () => {
    const result = buildIntegrityLinkExport(
      [], parseIntegrityLinkExportOptions({}), "capture-1",
    );
    expect(result.rows).toBe(0);
    expect(result.content).toContain("auditId,originalAuditId,action");
  });
  it.each([
    null, [], "bad", { format: "xml" }, { kind: "scores" },
    { maxRows: 0 }, { maxRows: 100001 }, { maxRows: 1.5 },
    { maxRows: "10" }, { unknown: true }, { action: "DELETE" },
    { since: "yesterday" }, { sort: "random" },
  ])("rejects invalid export options: %j", value => {
    expect(() => parseIntegrityLinkExportOptions(value)).toThrow();
  });
  it("rejects malformed capture identifiers", () => {
    expect(() => buildIntegrityLinkExport(
      [], parseIntegrityLinkExportOptions({}), "bad",
    )).toThrow("capture");
  });
});
