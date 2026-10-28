import { describe, expect, it } from "vitest";
import { extractDmarcPolicy, inventoryDmarcTxtRecords } from "./exposure-dmarc";

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

describe("passive DMARC policy extraction", () => {
  it("extracts the unambiguous policy tag", () => {
    expect(extractDmarcPolicy(["v=DMARC1; p=reject; rua=mailto:report@example.test"])).toBe("reject");
    expect(extractDmarcPolicy(["V=DMARC1; P = Quarantine"])).toBe("quarantine");
    expect(extractDmarcPolicy(["v=DMARC1; p=none"])).toBe("none");
  });
  it("fails closed on missing, duplicate, invalid or ambiguous policy tags", () => {
    expect(extractDmarcPolicy([])).toBeNull();
    expect(extractDmarcPolicy(["v=DMARC1; rua=mailto:a@example.test"])).toBeNull();
    expect(extractDmarcPolicy(["v=DMARC1; p=reject; p=none"])).toBeNull();
    expect(extractDmarcPolicy(["v=DMARC1; p=invalid"])).toBeNull();
    expect(extractDmarcPolicy(["v=DMARC1; p=none", "v=DMARC1; p=reject"])).toBeNull();
  });
});
