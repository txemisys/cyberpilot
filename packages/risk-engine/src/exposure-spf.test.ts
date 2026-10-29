import { describe, expect, it } from "vitest";
import { inventorySpfTxtRecords, extractSpfAllQualifier, extractSpfRedirect, extractSpfIncludes } from "./exposure-spf";

describe("passive SPF inventory", () => {
  it("ignores unrelated TXT records and SPF lookalikes", () => {
    expect(inventorySpfTxtRecords(["google-site-verification=abc", "v=spf10 -all"])).toEqual({
      status: "MISSING", records: [],
    });
  });
  it("recognizes a single case-insensitive SPF version token", () => {
    expect(inventorySpfTxtRecords(["  V=SPF1 -all  ", "other=record"])).toEqual({
      status: "PRESENT", records: ["  V=SPF1 -all  "],
    });
  });
  it("flags multiple SPF policies without claiming a validated security posture", () => {
    expect(inventorySpfTxtRecords(["v=spf1 -all", "v=spf1 include:_spf.example.test ~all"]).status).toBe("MULTIPLE");
  });
});

describe("SPF all qualifier", () => {
  it("parses one explicit all token", () => {
    expect(extractSpfAllQualifier(["v=spf1 -all"])).toBe("fail");
    expect(extractSpfAllQualifier(["v=spf1 ~all"])).toBe("softfail");
    expect(extractSpfAllQualifier(["v=spf1 ?all"])).toBe("neutral");
    expect(extractSpfAllQualifier(["v=spf1 +all"])).toBe("pass");
  });
  it("does not interpret missing or ambiguous all as verification", () => {
    expect(extractSpfAllQualifier(["v=spf1 ip4:192.0.2.1"])).toBeNull();
    expect(extractSpfAllQualifier(["v=spf1 -all ~all"])).toBeNull();
    expect(extractSpfAllQualifier(["v=spf1 -all", "v=spf1 ~all"])).toBeNull();
  });
});

describe("SPF redirect target", () => {
  it("extracts explicit DNS target without resolving it", () => {
    expect(extractSpfRedirect(["v=spf1 include:_spf.example.test redirect=Mail.Example.test"])).toBe("mail.example.test");
  });
  it("returns unknown for missing, repeated, invalid or multiple SPF records", () => {
    expect(extractSpfRedirect(["v=spf1 -all"])).toBeNull();
    expect(extractSpfRedirect(["v=spf1 redirect=a.test redirect=b.test"])).toBeNull();
    expect(extractSpfRedirect(["v=spf1 redirect=invalid..test"])).toBeNull();
    expect(extractSpfRedirect(["v=spf1 redirect=a.test", "v=spf1 -all"])).toBeNull();
  });
});

describe("passive SPF include mechanisms", () => {
  it("returns a list of DNS targets but does not resolve them", () => {
    expect(extractSpfIncludes(["v=spf1 include:_spf.Example.test ~include:backup.example.test -all"])).toEqual([
      "_spf.example.test", "backup.example.test",
    ]);
  });
  it("returns empty list for no include, and unknown on ambiguous or invalid records", () => {
    expect(extractSpfIncludes(["v=spf1 -all"])).toEqual([]);
    expect(extractSpfIncludes([])).toBeNull();
    expect(extractSpfIncludes(["v=spf1 include:a.test", "v=spf1 include:b.test"])).toBeNull();
    expect(extractSpfIncludes(["v=spf1 include:bad..test"])).toBeNull();
  });
});
