import { describe, expect, it } from "vitest";
import { inventoryDmarcTxtRecords } from "./exposure-dmarc";

describe("passive DMARC record inventory", () => {
  it("does not count unrelated records or lookalike versions", () => {
    expect(inventoryDmarcTxtRecords(["v=DMARC10; p=reject", "other=record"])).toEqual({
      status: "MISSING", records: [],
    });
  });
  it("recognizes a single DMARC version marker without asserting the policy is valid", () => {
    expect(inventoryDmarcTxtRecords([" V=DMARC1; p=none ", "other=record"])).toEqual({
      status: "PRESENT", records: [" V=DMARC1; p=none "],
    });
  });
  it("detects multiple records at the same DMARC query name", () => {
    expect(inventoryDmarcTxtRecords(["v=DMARC1; p=none", "v=DMARC1; p=reject"]).status).toBe("MULTIPLE");
  });
});
