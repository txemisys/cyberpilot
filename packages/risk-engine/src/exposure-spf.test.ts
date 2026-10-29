import { describe, expect, it } from "vitest";
import { inventorySpfTxtRecords, extractSpfAllQualifier } from "./exposure-spf";

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
