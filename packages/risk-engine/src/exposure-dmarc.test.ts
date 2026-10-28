import { describe, expect, it } from "vitest";
import { extractDmarcAlignment, extractDmarcPercentage, extractDmarcPolicy, extractDmarcSubdomainPolicy, inventoryDmarcTxtRecords } from "./exposure-dmarc";

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

describe("explicit DMARC subdomain policy", () => {
  it("extracts an explicit sp tag independently of p", () => {
    expect(extractDmarcSubdomainPolicy(["v=DMARC1; p=none; sp=reject"])).toBe("reject");
    expect(extractDmarcSubdomainPolicy(["v=DMARC1; p=reject; SP = Quarantine"])).toBe("quarantine");
  });
  it("does not invent inherited policy or accept repeated or malformed tags", () => {
    expect(extractDmarcSubdomainPolicy(["v=DMARC1; p=reject"])).toBeNull();
    expect(extractDmarcSubdomainPolicy(["v=DMARC1; sp=none; sp=reject"])).toBeNull();
    expect(extractDmarcSubdomainPolicy(["v=DMARC1; sp=invalid"])).toBeNull();
    expect(extractDmarcSubdomainPolicy(["v=DMARC1; sp=none", "v=DMARC1; sp=reject"])).toBeNull();
  });
});

describe("explicit DMARC percentage", () => {
  it("extracts configured values from 0 through 100", () => {
    expect(extractDmarcPercentage(["v=DMARC1; p=reject; pct=0"])).toBe(0);
    expect(extractDmarcPercentage(["v=DMARC1; p=reject; PCT = 100"])).toBe(100);
  });
  it("rejects absent, malformed, duplicate or out-of-range values", () => {
    expect(extractDmarcPercentage(["v=DMARC1; p=reject"])).toBeNull();
    expect(extractDmarcPercentage(["v=DMARC1; pct=101"])).toBeNull();
    expect(extractDmarcPercentage(["v=DMARC1; pct=-1"])).toBeNull();
    expect(extractDmarcPercentage(["v=DMARC1; pct=20; pct=50"])).toBeNull();
    expect(extractDmarcPercentage(["v=DMARC1; pct=50", "v=DMARC1; pct=100"])).toBeNull();
  });
});

describe("explicit DMARC alignment", () => {
  it("extracts strict and relaxed modes independently", () => {
    expect(extractDmarcAlignment(["v=DMARC1; p=reject; adkim=s; aspf=r"], "adkim")).toBe("strict");
    expect(extractDmarcAlignment(["v=DMARC1; p=reject; adkim=s; aspf=r"], "aspf")).toBe("relaxed");
  });
  it("does not infer defaults and rejects malformed or duplicate values", () => {
    expect(extractDmarcAlignment(["v=DMARC1; p=reject"], "adkim")).toBeNull();
    expect(extractDmarcAlignment(["v=DMARC1; adkim=x"], "adkim")).toBeNull();
    expect(extractDmarcAlignment(["v=DMARC1; adkim=s; adkim=r"], "adkim")).toBeNull();
    expect(extractDmarcAlignment(["v=DMARC1; aspf=s", "v=DMARC1; aspf=r"], "aspf")).toBeNull();
  });
});
