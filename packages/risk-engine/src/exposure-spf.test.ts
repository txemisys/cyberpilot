import { describe, expect, it } from "vitest";
import { inventorySpfTxtRecords } from "./exposure-spf";

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
