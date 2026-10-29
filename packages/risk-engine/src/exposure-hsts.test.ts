import { describe, expect, it } from "vitest";
import { extractHstsMaxAge } from "./exposure-hsts";

describe("passive HSTS max-age", () => {
  it("extracts nonnegative seconds without asserting HSTS is secure", () => {
    expect(extractHstsMaxAge("max-age=31536000; includeSubDomains")).toBe(31536000);
    expect(extractHstsMaxAge("MAX-AGE = 0")).toBe(0);
  });
  it("rejects missing, duplicated, malformed and unsafe max-age values", () => {
    expect(extractHstsMaxAge(null)).toBeNull();
    expect(extractHstsMaxAge("includeSubDomains")).toBeNull();
    expect(extractHstsMaxAge("max-age=10; max-age=20")).toBeNull();
    expect(extractHstsMaxAge("max-age=-1")).toBeNull();
    expect(extractHstsMaxAge("max-age=9007199254740993")).toBeNull();
  });
});
