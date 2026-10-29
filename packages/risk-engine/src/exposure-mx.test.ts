import { describe, expect, it } from "vitest";
import { inventoryMxRecords, summarizeMxRouting, groupMxByPreference } from "./exposure-mx";

describe("passive MX inventory", () => {
  it("distinguishes no supplied MX records from present ones", () => {
    expect(inventoryMxRecords([])).toEqual({ status: "MISSING", records: [] });
    const records = [{ priority: 10, exchange: "mail.example.test." }];
    expect(inventoryMxRecords(records)).toEqual({ status: "PRESENT", records });
  });
  it("identifies a null MX explicitly rather than reporting a mail exchanger", () => {
    expect(inventoryMxRecords([{ priority: 0, exchange: "." }])).toEqual({ status: "NULL_MX", records: [{ priority: 0, exchange: "." }] });
  });
  it("deduplicates case-insensitive equivalent MX answers", () => {
    expect(inventoryMxRecords([
      { priority: 10, exchange: "MAIL.EXAMPLE.TEST." },
      { priority: 10, exchange: "mail.example.test" },
      { priority: 20, exchange: "backup.example.test" },
    ])).toEqual({
      status: "PRESENT",
      records: [
        { priority: 10, exchange: "MAIL.EXAMPLE.TEST." },
        { priority: 20, exchange: "backup.example.test" },
      ],
    });
  });
  it("retains distinct MX priorities for the same exchange", () => {
    const result = inventoryMxRecords([{ priority: 10, exchange: "mail.example.test" }, { priority: 20, exchange: "MAIL.EXAMPLE.TEST." }]);
    expect(result.records).toHaveLength(2);
  });
  it("rejects invalid null MX combinations", () => {
    expect(inventoryMxRecords([{ priority: 10, exchange: "." }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 0, exchange: "." }, { priority: 10, exchange: "mail.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 0, exchange: "." }, { priority: 0, exchange: "." }]).status).toBe("INVALID");
  });
  it("rejects DNS host labels longer than 63 characters", () => {
    const oversized = "a".repeat(64) + ".example.test";
    expect(inventoryMxRecords([{ priority: 10, exchange: oversized }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 10, exchange: "-mail.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 10, exchange: "mail-.example.test" }]).status).toBe("INVALID");
  });
  it("fails closed on malformed priority or hostname", () => {
    expect(inventoryMxRecords([{ priority: -1, exchange: "mx.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 65536, exchange: "mx.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 1.5, exchange: "mx.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 10, exchange: "bad host" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 10, exchange: "mx.example.test" }, { priority: 20, exchange: "" }])).toEqual({ status: "INVALID", records: [] });
  });
});

describe("passive MX routing summary", () => {
  it("groups equal-minimum preference routes and backup routes", () => {
    expect(summarizeMxRouting([
      { priority: 20, exchange: "backup.test" },
      { priority: 10, exchange: "primary-a.test" },
      { priority: 10, exchange: "primary-b.test" },
      { priority: 10, exchange: "PRIMARY-A.TEST." },
    ])).toEqual({
      status: "PRESENT",
      primaryExchanges: ["primary-a.test", "primary-b.test"],
      backupExchanges: ["backup.test"],
      distinctExchangeCount: 3,
      lowestPreference: 10,
      preferenceTiers: [10, 20],
      preferenceTierCount: 2,
    });
  });
  it("does not mistake null MX or invalid data for a routable mail exchange", () => {
    expect(summarizeMxRouting([])).toEqual({ status: "MISSING", primaryExchanges: [], backupExchanges: [], distinctExchangeCount: 0, lowestPreference: null, preferenceTiers: [], preferenceTierCount: 0 });
    expect(summarizeMxRouting([{ priority: 0, exchange: "." }])).toEqual({ status: "NULL_MX", primaryExchanges: [], backupExchanges: [], distinctExchangeCount: 0, lowestPreference: null, preferenceTiers: [], preferenceTierCount: 0 });
    expect(summarizeMxRouting([{ priority: -1, exchange: "broken.test" }])).toEqual({ status: "INVALID", primaryExchanges: [], backupExchanges: [], distinctExchangeCount: 0, lowestPreference: null, preferenceTiers: [], preferenceTierCount: 0 });
  });
});

describe("MX distinct-host metric", () => {
  it("counts the same MX hostname only once across priorities", () => {
    expect(summarizeMxRouting([
      { priority: 10, exchange: "mail.example.test" },
      { priority: 20, exchange: "MAIL.EXAMPLE.TEST." },
      { priority: 30, exchange: "backup.example.test" },
    ]).distinctExchangeCount).toBe(2);
  });
});

describe("MX preference tiers", () => {
  it("counts unique priority tiers", () => {
    expect(summarizeMxRouting([
      { priority: 5, exchange: "a.test" },
      { priority: 5, exchange: "b.test" },
      { priority: 20, exchange: "c.test" },
    ]).preferenceTierCount).toBe(2);
  });

  it("orders unique preference values without modifying the source order", () => {
    expect(summarizeMxRouting([
      { priority: 30, exchange: "c.example.test" },
      { priority: 10, exchange: "a.example.test" },
      { priority: 20, exchange: "b.example.test" },
      { priority: 10, exchange: "d.example.test" },
    ]).preferenceTiers).toEqual([10, 20, 30]);
  });
});

describe("passive MX preference groups", () => {
  it("groups all levels in ascending preference order, retaining exchanges per tier", () => {
    expect(groupMxByPreference([
      { priority: 30, exchange: "backup.test" },
      { priority: 10, exchange: "primary-a.test" },
      { priority: 10, exchange: "primary-b.test" },
      { priority: 20, exchange: "middle.test" },
    ])).toEqual({
      status: "PRESENT",
      groups: [
        { priority: 10, exchanges: ["primary-a.test", "primary-b.test"] },
        { priority: 20, exchanges: ["middle.test"] },
        { priority: 30, exchanges: ["backup.test"] },
      ],
    });
  });
  it("never infers MX preference groups for missing, null or invalid MX", () => {
    expect(groupMxByPreference([])).toEqual({ status: "MISSING", groups: [] });
    expect(groupMxByPreference([{ priority: 0, exchange: "." }])).toEqual({ status: "NULL_MX", groups: [] });
    expect(groupMxByPreference([{ priority: -1, exchange: "mail.test" }])).toEqual({ status: "INVALID", groups: [] });
  });
});

describe("MX preference grouping normalization", () => {
  it("does not duplicate equivalent records in the same priority group", () => {
    expect(groupMxByPreference([
      { priority: 10, exchange: "MAIL.EXAMPLE.TEST." },
      { priority: 10, exchange: "mail.example.test" },
      { priority: 20, exchange: "backup.example.test" },
    ])).toEqual({
      status: "PRESENT",
      groups: [
        { priority: 10, exchanges: ["MAIL.EXAMPLE.TEST."] },
        { priority: 20, exchanges: ["backup.example.test"] },
      ],
    });
  });
});
