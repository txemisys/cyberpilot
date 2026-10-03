import { describe, expect, it } from "vitest";

import { analyzeDmarcRecords, analyzeSpfRecords } from "./index";

describe("analyzeSpfRecords", () => {
  it("detects a single SPF record", () => {
    expect(analyzeSpfRecords(["v=spf1 include:spf.protection.outlook.com -all"]))
      .toEqual({
        status: "PRESENT",
        records: ["v=spf1 include:spf.protection.outlook.com -all"],
      });
  });

  it("detects multiple SPF records", () => {
    expect(
      analyzeSpfRecords(["v=spf1 -all", "v=spf1 include:example.com -all"]),
    ).toMatchObject({ status: "MULTIPLE" });
  });

  it("ignores unrelated TXT records", () => {
    expect(analyzeSpfRecords(["google-site-verification=abc"])).toEqual({
      status: "MISSING",
      records: [],
    });
  });
});

describe("analyzeDmarcRecords", () => {
  it("detects monitoring-only DMARC", () => {
    expect(
      analyzeDmarcRecords(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]),
    ).toMatchObject({
      status: "MONITORING",
      policy: "none",
    });
  });

  it("detects enforcing DMARC", () => {
    expect(analyzeDmarcRecords(["v=DMARC1; p=reject"])).toMatchObject({
      status: "ENFORCING",
      policy: "reject",
    });
  });

  it("treats multiple DMARC policy records as invalid", () => {
    expect(
      analyzeDmarcRecords(["v=DMARC1; p=none", "v=DMARC1; p=reject"]),
    ).toMatchObject({
      status: "INVALID",
    });
  });
});
