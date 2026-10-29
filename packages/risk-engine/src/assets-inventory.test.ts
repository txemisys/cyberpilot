import { describe, expect, it } from "vitest";
import { ASSET_COLUMNS, parseAssetCsv } from "./assets-csv";
import { ASSET_HYGIENE_RULES, assessAssetInventory, summarizeAssetInventory } from "./assets-assessment";
import type { AssetRecord } from "./assets-csv";
const header = ASSET_COLUMNS.join(",");
const row = ["id-001","SERVER","srv.example.test","ops","Linux","1","192.0.2.1","HIGH","HQ","ACTIVE"].join(",");
const record: AssetRecord = { assetId:"id-001",kind:"SERVER",hostname:"srv.example.test",owner:"ops",os:"Linux",osVersion:"1",ip:"192.0.2.1",criticality:"HIGH",location:"HQ",lifecycle:"ACTIVE" };
describe("asset CSV import and hygiene", () => {
  it("parses a complete row", () => {
    expect(parseAssetCsv(header+"\n"+row).records).toEqual([record]);
  });
  it("handles quoted commas and escaped quotes", () => {
    const value = row.replace("srv.example.test", '"srv, \"\"host\"\""');
    expect(parseAssetCsv(header+"\n"+value).records[0]?.hostname).toBe('srv, "host"');
  });
  it("rejects invalid headers and unterminated quotes", () => {
    expect(parseAssetCsv("bad\n"+row).issues[0]?.code).toBe("INVALID_HEADER");
    expect(parseAssetCsv(header+'\n"unfinished').issues[0]?.code).toBe("INVALID_CSV");
  });
  it("rejects oversized files and rows", () => {
    expect(parseAssetCsv("x".repeat(5_000_001)).issues[0]?.code).toBe("FILE_TOO_LARGE");
    expect(parseAssetCsv(header+"\n"+row+"\n"+row,1).issues[0]?.code).toBe("TOO_MANY_ROWS");
  });
  it("rejects malformed rows and duplicates", () => {
    expect(parseAssetCsv(header+"\n"+row+"\n"+row).duplicateIds).toEqual(["id-001"]);
    expect(parseAssetCsv(header+"\nshort,row").issues[0]?.code).toBe("COLUMN_COUNT");
  });
  it("rejects invalid identifiers, enums and long values", () => {
    expect(parseAssetCsv(header+"\n"+row.replace("id-001","invalid id")).issues[0]?.code).toBe("INVALID_ID");
    expect(parseAssetCsv(header+"\n"+row.replace("SERVER","BIRD")).issues[0]?.code).toBe("INVALID_ENUM");
    expect(parseAssetCsv(header+"\n"+row.replace("srv.example.test","a".repeat(513))).issues[0]?.code).toBe("FIELD_TOO_LONG");
  });
  it("assesses missing fields as declarations rather than verified vulnerabilities", () => {
    const findings = assessAssetInventory([{...record,owner:"",hostname:"",criticality:"CRITICAL"}]);
    expect(findings.map(x=>x.code)).toContain("MISSING_OWNER");
    expect(findings.map(x=>x.code)).toContain("CRITICAL_ASSET_WITHOUT_OWNER");
    expect(findings.every(x=>x.source==="DECLARED")).toBe(true);
  });
  it("does not assess retired assets as active hygiene gaps", () => {
    expect(assessAssetInventory([{...record,owner:"",lifecycle:"RETIRED"}])).toEqual([]);
  });
  it("summarizes inventory without turning it into a score", () => {
    expect(summarizeAssetInventory([record,{...record,assetId:"id-2",lifecycle:"RETIRED"}])).toEqual({
      total:2,active:1,retired:1,unknownLifecycle:0,withoutOwner:0,critical:0,byKind:{SERVER:2},
    });
  });
  it("keeps rule codes unique", () => {
    expect(new Set(ASSET_HYGIENE_RULES.map(x=>x[0])).size).toBe(ASSET_HYGIENE_RULES.length);
  });
});
