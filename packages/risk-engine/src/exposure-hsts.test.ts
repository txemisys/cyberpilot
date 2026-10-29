import { describe, expect, it } from "vitest";
import { extractHstsMaxAge, inspectHstsFlags } from "./exposure-hsts";

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

describe("passive HSTS directives", () => {
  it("distinguishes the two optional directives without claiming HSTS enforcement", () => {
    expect(inspectHstsFlags("max-age=31536000; includeSubDomains; preload")).toEqual({
      includeSubDomains: true, preload: true,
    });
    expect(inspectHstsFlags("max-age=0")).toEqual({ includeSubDomains: false, preload: false });
  });
  it("fails closed on invalid age, duplicate directives or malformed flag values", () => {
    expect(inspectHstsFlags("includeSubDomains")).toBeNull();
    expect(inspectHstsFlags("max-age=5; preload; PRELOAD")).toBeNull();
    expect(inspectHstsFlags("max-age=5; includeSubDomains=true")).toBeNull();
  });
});
