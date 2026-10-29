import { describe, expect, it } from "vitest";
import { inventoryDkimTxtRecords } from "./exposure-dkim";

describe("DKIM inventory", () => {
  it("returns missing for empty input", () => {
    expect(inventoryDkimTxtRecords([])).toEqual({ status: "MISSING", records: [] });
  });
  it("recognizes an explicit DKIM version", () => {
    expect(inventoryDkimTxtRecords(["v=DKIM1; p=abc"]).status).toBe("PRESENT");
  });
  it("recognizes multiple candidates", () => {
    expect(inventoryDkimTxtRecords(["v=DKIM1; p=abc", "V=DKIM1; p=xyz"]).status).toBe("MULTIPLE");
  });
  it("rejects unrelated versions", () => {
    expect(inventoryDkimTxtRecords(["v=DKIM12; p=abc"]).status).toBe("MISSING");
  });
});
