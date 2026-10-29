import { describe, expect, it } from "vitest";
import { inventoryMxRecords } from "./exposure-mx";

describe("passive MX inventory", () => {
  it("distinguishes no supplied MX records from present ones", () => {
    expect(inventoryMxRecords([])).toEqual({ status: "MISSING", records: [] });
    const records = [{ priority: 10, exchange: "mail.example.test." }];
    expect(inventoryMxRecords(records)).toEqual({ status: "PRESENT", records });
  });
  it("recognizes a null MX record but does not infer mail delivery capability", () => {
    expect(inventoryMxRecords([{ priority: 0, exchange: "." }]).status).toBe("PRESENT");
  });
  it("fails closed on malformed priority or hostname", () => {
    expect(inventoryMxRecords([{ priority: -1, exchange: "mx.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 65536, exchange: "mx.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 1.5, exchange: "mx.example.test" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 10, exchange: "bad host" }]).status).toBe("INVALID");
    expect(inventoryMxRecords([{ priority: 10, exchange: "mx.example.test" }, { priority: 20, exchange: "" }])).toEqual({ status: "INVALID", records: [] });
  });
});
