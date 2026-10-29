import { describe, expect, it } from "vitest";
import { classifyHttpStatus, inspectHttpScheme, inspectRedirect, inventoryResponseHeaders, inspectPermissionsPolicy, inspectXFrameOptions } from "./exposure-http-observation";
describe("offline HTTP observations", () => {
  it.each([[null,"UNKNOWN"],[99,"INVALID"],[100,"INFORMATIONAL"],[200,"SUCCESS"],[302,"REDIRECT"],[404,"CLIENT_ERROR"],[503,"SERVER_ERROR"],[600,"INVALID"],[200.5,"INVALID"]] as const)("classifies status %s", (status, category) => {
    expect(classifyHttpStatus(status)).toBe(category);
  });
  it("classifies URL schemes and unknown input", () => {
    expect(inspectHttpScheme("https://example.test")).toBe("HTTPS");
    expect(inspectHttpScheme("http://example.test")).toBe("HTTP");
    expect(inspectHttpScheme("ftp://example.test")).toBe("OTHER");
    expect(inspectHttpScheme("invalid")).toBe("UNKNOWN");
  });
  it("inspects same-origin and cross-origin redirects without following them", () => {
    expect(inspectRedirect({ url: "https://example.test/a", status: 301, location: "/b" })).toEqual({
      state: "VALID_TARGET", target: "https://example.test/b", crossOrigin: false, downgrade: false,
    });
    expect(inspectRedirect({ url: "https://example.test/a", status: 302, location: "http://else.test/" })).toEqual({
      state: "VALID_TARGET", target: "http://else.test/", crossOrigin: true, downgrade: true,
    });
  });
  it("distinguishes absent, missing-target and unsafe redirects", () => {
    expect(inspectRedirect({}).state).toBe("UNKNOWN");
    expect(inspectRedirect({ status: 200 }).state).toBe("NOT_REDIRECT");
    expect(inspectRedirect({ status: 301 }).state).toBe("MISSING_TARGET");
    expect(inspectRedirect({ url: "https://example.test", status: 302, location: "javascript:alert(1)" }).state).toBe("INVALID_TARGET");
  });
  it("normalizes headers while preserving duplicate and empty evidence", () => {
    expect(inventoryResponseHeaders([["CSP", "yes"], ["csp", "  "], ["X-Test", "ok"]])).toEqual({
      state: "COLLECTED", names: ["csp", "x-test"], duplicateNames: ["csp"], emptyNames: ["csp"],
    });
    expect(inventoryResponseHeaders(null).state).toBe("UNKNOWN");
    expect(inventoryResponseHeaders([]).state).toBe("COLLECTED");
  });
  it("inspects Permissions-Policy feature names conservatively", () => {
    expect(inspectPermissionsPolicy("camera=(), geolocation=(self)")).toEqual(["camera", "geolocation"]);
    expect(inspectPermissionsPolicy("camera=(), camera=(self)")).toBeNull();
    expect(inspectPermissionsPolicy("bad format")).toBeNull();
    expect(inspectPermissionsPolicy(undefined)).toBeNull();
  });
  it("distinguishes X-Frame-Options configured, missing and invalid", () => {
    expect(inspectXFrameOptions(" deny ")).toBe("DENY");
    expect(inspectXFrameOptions("SAMEORIGIN")).toBe("SAMEORIGIN");
    expect(inspectXFrameOptions("ALLOW-FROM x")).toBe("INVALID");
    expect(inspectXFrameOptions(null)).toBe("MISSING");
  });
});
