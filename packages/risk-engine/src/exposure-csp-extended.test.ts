import { describe, expect, it } from "vitest";
import { parseCspDirectives, extractCspSources, inspectCspFlag, inventoryCspUnsafeSources, inspectCspEvidence } from "./exposure-csp-extended";
describe("extended passive CSP evidence", () => {
  const value = "default-src 'self'; form-action 'self'; connect-src https://api.example.test; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-eval'; upgrade-insecure-requests; block-all-mixed-content";
  it("parses directive names and tokens only from supplied data", () => {
    expect(parseCspDirectives(value)?.[0]).toEqual({ name: "default-src", tokens: ["'self'"] });
    expect(extractCspSources(value, "form-action")).toEqual(["'self'"]);
    expect(extractCspSources(value, "connect-src")).toEqual(["https://api.example.test"]);
    expect(extractCspSources(value, "img-src")).toEqual(["data:"]);
    expect(extractCspSources(value, "style-src")).toEqual(["'unsafe-inline'"]);
    expect(extractCspSources("default-src 'self'", "img-src")).toBeNull();
  });
  it("only calls a present valueless CSP flag present", () => {
    expect(inspectCspFlag(value, "upgrade-insecure-requests")).toBe("PRESENT");
    expect(inspectCspFlag(value, "block-all-mixed-content")).toBe("PRESENT");
    expect(inspectCspFlag("default-src 'self'", "upgrade-insecure-requests")).toBe("MISSING");
    expect(inspectCspFlag("upgrade-insecure-requests value", "upgrade-insecure-requests")).toBe("INVALID");
    expect(inspectCspFlag(null, "upgrade-insecure-requests")).toBe("UNKNOWN");
  });
  it("reports declared unsafe expression names without claiming effective enforcement", () => {
    expect(inventoryCspUnsafeSources(value)).toEqual({ unsafeInline: ["style-src"], unsafeEval: ["script-src"] });
    expect(inventoryCspUnsafeSources(null)).toBeNull();
    expect(inventoryCspUnsafeSources("script-src a; script-src b")).toBeNull();
  });
  it("does not pretend declared policies were observed or accept undated observed evidence", () => {
    expect(inspectCspEvidence({ source: "DECLARED", policy: value }).state).toBe("DECLARED");
    expect(inspectCspEvidence({ source: "OBSERVED", policy: value }).state).toBe("INVALID");
    expect(inspectCspEvidence({ source: "OBSERVED", policy: value, observedAt: "2026-10-29T12:00:00Z" }).state).toBe("OBSERVED");
    expect(inspectCspEvidence({ source: "DECLARED", policy: null }).state).toBe("UNKNOWN");
  });
  it("rejects ambiguous directive inventories", () => {
    expect(parseCspDirectives("script-src a; SCRIPT-SRC b")).toBeNull();
    expect(parseCspDirectives("bad@directive x")).toBeNull();
  });
});
