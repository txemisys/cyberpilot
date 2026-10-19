import { describe, expect, it } from "vitest";

import {
  analyzeDmarcRecords,
  analyzeSpfRecords,
  observeDomainSecurity,
} from "./index";

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


describe("observeDomainSecurity DNS bounds", () => {
  it("treats timed-out lookups as ERROR and cancels outstanding DNS work", async () => {
    let cancelCount = 0;

    const resolver = {
      resolveTxt: async () => new Promise<string[][]>(() => {}),
      resolveCname: async () => new Promise<string[]>(() => {}),
      cancel() {
        cancelCount += 1;
      },
    };

    const observation = await observeDomainSecurity("Example.COM", {
      resolverFactory: () => resolver,
      queryTimeoutMs: 5,
    });

    expect(observation.name).toBe("example.com");
    expect(observation.spf.status).toBe("ERROR");
    expect(observation.dmarc.status).toBe("ERROR");
    expect(observation.dkim.status).toBe("ERROR");
    expect(cancelCount).toBe(4);
  });

  it("keeps ordinary no-record DNS responses distinct from resolver failures", async () => {
    const missing = Object.assign(new Error("No data"), { code: "ENODATA" });

    const observation = await observeDomainSecurity("example.com", {
      resolverFactory: () => ({
        resolveTxt: async () => {
          throw missing;
        },
        resolveCname: async () => {
          throw missing;
        },
        cancel() {},
      }),
      queryTimeoutMs: 50,
    });

    expect(observation.spf.status).toBe("MISSING");
    expect(observation.dmarc.status).toBe("MISSING");
    expect(observation.dkim.status).toBe("MISSING");
  });

  it("uses resolved DNS evidence when lookups complete inside the bound", async () => {
    const observation = await observeDomainSecurity("Example.COM", {
      resolverFactory: () => ({
        async resolveTxt(name) {
          if (name.startsWith("_dmarc.")) {
            return [["v=DMARC1; p=reject"]];
          }

          return [["v=spf1", " -all"]];
        },
        async resolveCname(name) {
          return [`${name}.target.example`];
        },
        cancel() {},
      }),
      queryTimeoutMs: 50,
    });

    expect(observation.name).toBe("example.com");
    expect(observation.spf.status).toBe("PRESENT");
    expect(observation.dmarc.status).toBe("ENFORCING");
    expect(observation.dkim.status).toBe("PUBLISHED");
  });
});
