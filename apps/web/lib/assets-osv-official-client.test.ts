import { describe, expect, it, vi } from "vitest";
import {
  OSV_API_ORIGIN, OSV_QUERY_PATH, validateLiveOsvRequest,
  buildLiveOsvPayload, parseLiveOsvPage, queryOfficialOsv,
} from "./assets-osv-official-client";
const request = { ecosystem: "npm", name: "example-package", version: "1.2.3" };
const now = () => new Date("2026-11-05T12:00:00.000Z");
const vuln = {
  id: "GHSA-abcd-1234-5678",
  modified: "2026-11-01T12:00:00Z",
  aliases: ["CVE-2026-12345"],
  affected: [{
    package: { ecosystem: "npm", name: "example-package" },
    versions: ["1.2.3"],
  }],
};
const response = (data: unknown, status = 200, headers?: HeadersInit) =>
  new Response(JSON.stringify(data), {
    status, headers: { "content-type": "application/json", ...headers },
  });
describe("official OSV fixed endpoint client validation", () => {
  it("uses the documented HTTPS query origin and path", () => {
    expect(OSV_API_ORIGIN + OSV_QUERY_PATH)
      .toBe("https://api.osv.dev/v1/query");
  });
  it("builds exact package-and-version query without a versioned PURL", () => {
    expect(buildLiveOsvPayload(request)).toEqual({
      version: "1.2.3",
      package: { ecosystem: "npm", name: "example-package" },
    });
    expect(buildLiveOsvPayload({
      ...request, expectedPurl: "pkg:npm/example-package",
    })).toEqual({
      version: "1.2.3",
      package: { purl: "pkg:npm/example-package" },
    });
  });
  it.each([
    { ...request, name: "https://attacker.invalid" },
    { ...request, name: "../api/internal" },
    { ...request, name: "package\nsecond" },
    { ...request, version: "latest" },
    { ...request, version: "1.0.*" },
    { ...request, ecosystem: "npm\nOther" },
    { ...request, expectedPurl: "https://invalid.example" },
    { ...request, expectedPurl: "pkg:npm/example-package@1.2.3" },
    { ...request, endpoint: "https://evil.example" },
  ])("rejects disallowed package query input", value => {
    expect(() => validateLiveOsvRequest(value)).toThrow();
  });
  it("rejects malicious pagination tokens", () => {
    expect(() => buildLiveOsvPayload(request, "a b")).toThrow();
    expect(() => buildLiveOsvPayload(request, "../internal")).toThrow();
    expect(buildLiveOsvPayload(request, "base64=="))
      .toHaveProperty("page_token", "base64==");
  });
  it("recognizes a literal enumerated affected package-version", () => {
    const raw = JSON.stringify({ vulns: [vuln] });
    const page = parseLiveOsvPage(JSON.parse(raw), request, raw);
    expect(page.references[0]).toMatchObject({
      id: vuln.id, exactVersionListed: true,
      packageIdentityListed: true, rangesPresent: false,
      withdrawn: null,
    });
    expect(page.responseDigest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("does not treat provider fuzzy matches as literal affected versions", () => {
    const fuzzy = {
      ...vuln,
      affected: [{
        package: { ecosystem: "npm", name: "example-package" },
        versions: ["1.2.4"],
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
      }],
    };
    const raw = JSON.stringify({ vulns: [fuzzy] });
    const page = parseLiveOsvPage(JSON.parse(raw), request, raw);
    expect(page.references[0]?.exactVersionListed).toBe(false);
    expect(page.references[0]?.rangesPresent).toBe(true);
  });
  it("flags package identity mismatches rather than trusting the provider", () => {
    const mismatched = {
      ...vuln, affected: [{
        package: { ecosystem: "PyPI", name: "example-package" },
        versions: ["1.2.3"],
      }],
    };
    const raw = JSON.stringify({ vulns: [mismatched] });
    const page = parseLiveOsvPage(JSON.parse(raw), request, raw);
    expect(page.references[0]?.packageIdentityListed).toBe(false);
    expect(page.references[0]?.exactVersionListed).toBe(false);
  });
  it("never marks withdrawn records as active", () => {
    const withdrawn = { ...vuln, withdrawn: "2026-11-01T12:00:00Z" };
    const raw = JSON.stringify({ vulns: [withdrawn] });
    const page = parseLiveOsvPage(JSON.parse(raw), request, raw);
    expect(page.references[0]?.withdrawn).not.toBeNull();
  });
  it("rejects unexpected upstream records and malformed result containers", () => {
    expect(() => parseLiveOsvPage({ vulns: "bad" }, request, "{}")).toThrow();
    expect(() => parseLiveOsvPage({
      vulns: [{ id: "not valid id" }],
    }, request, "{}")).toThrow();
    expect(() => parseLiveOsvPage({
      next_page_token: "a b",
    }, request, "{}")).toThrow();
  });
});
describe("official OSV HTTPS pagination and failure boundaries", () => {
  it("queries an exact fixed endpoint, with no redirects or credentials", async () => {
    const mock = vi.fn<typeof fetch>().mockResolvedValue(response({
      vulns: [vuln],
    }));
    const report = await queryOfficialOsv(request, {
      fetchImpl: mock, now,
    });
    expect(mock).toHaveBeenCalledTimes(1);
    const [url, init] = mock.mock.calls[0]!;
    expect(url).toBe(OSV_API_ORIGIN + OSV_QUERY_PATH);
    expect(init).toMatchObject({
      method: "POST", redirect: "error", cache: "no-store",
    });
    expect(JSON.parse(String(init?.body))).toEqual(
      buildLiveOsvPayload(request));
    expect(report.status).toBe("COMPLETE");
    expect(report.exactEnumeratedCount).toBe(1);
    expect(report.providerReportedCount).toBe(1);
    expect(report.nonEnumeratedCount).toBe(0);
    expect(report.digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("follows bounded provider-issued pagination tokens", async () => {
    const mock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response({
        vulns: [vuln], next_page_token: "NEXT==",
      }))
      .mockResolvedValueOnce(response({
        vulns: [{
          ...vuln, id: "GHSA-bbbb-1234-5678",
        }],
      }));
    const result = await queryOfficialOsv(request, {
      fetchImpl: mock, now, maxPages: 2,
    });
    expect(mock).toHaveBeenCalledTimes(2);
    expect(JSON.parse(String(mock.mock.calls[1]?.[1]?.body)).page_token)
      .toBe("NEXT==");
    expect(result.status).toBe("COMPLETE");
    expect(result.queriedPages).toBe(2);
    expect(result.vulnerabilities).toHaveLength(2);
  });
  it("treats exceeded pagination budget as truncated", async () => {
    const mock = vi.fn<typeof fetch>().mockResolvedValue(response({
      vulns: [vuln], next_page_token: "NEXT==",
    }));
    const result = await queryOfficialOsv(request, {
      fetchImpl: mock, now, maxPages: 1,
    });
    expect(result.status).toBe("TRUNCATED");
    expect(result.queriedPages).toBe(1);
  });
  it("rejects repeated upstream page tokens without infinite loops", async () => {
    const mock = vi.fn<typeof fetch>().mockResolvedValue(response({
      vulns: [], next_page_token: "REPEAT==",
    }));
    const result = await queryOfficialOsv(request, {
      fetchImpl: mock, now, maxPages: 5,
    });
    expect(result.status).toBe("UPSTREAM_ERROR");
    expect(mock.mock.calls.length).toBeLessThanOrEqual(2);
  });
  it("rejects upstream HTTP errors conservatively", async () => {
    const mock = vi.fn<typeof fetch>().mockResolvedValue(response({
      message: "rate limited",
    }, 429));
    const result = await queryOfficialOsv(request, { fetchImpl: mock, now });
    expect(result.status).toBe("UPSTREAM_ERROR");
    expect(result.providerReportedCount).toBe(0);
  });
  it("rejects advertised oversized responses", async () => {
    const mock = vi.fn<typeof fetch>().mockResolvedValue(
      response({ vulns: [] }, 200, { "content-length": "500000" }));
    const result = await queryOfficialOsv(request, {
      fetchImpl: mock, now, maxResponseBytes: 4096,
    });
    expect(result.status).toBe("UPSTREAM_ERROR");
  });
  it("rejects actual oversized body even without response length", async () => {
    const huge = "X".repeat(9000);
    const mock = vi.fn<typeof fetch>().mockResolvedValue(
      response({ vulns: [], padding: huge }));
    const result = await queryOfficialOsv(request, {
      fetchImpl: mock, now, maxResponseBytes: 4096,
    });
    expect(result.status).toBe("UPSTREAM_ERROR");
  });
  it("does not silently treat malformed JSON as an empty source", async () => {
    const mock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response("{broken", { status: 200 }));
    const result = await queryOfficialOsv(request, { fetchImpl: mock, now });
    expect(result.status).toBe("UPSTREAM_ERROR");
  });
  it("does not allow duplicates with contradictory advisory content", async () => {
    const mock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(response({
        vulns: [vuln], next_page_token: "NEXT==",
      }))
      .mockResolvedValueOnce(response({
        vulns: [{
          ...vuln, affected: [{
            package: { ecosystem: "PyPI", name: "different" },
            versions: ["1.2.3"],
          }],
        }],
      }));
    const result = await queryOfficialOsv(request, {
      fetchImpl: mock, now,
    });
    expect(result.status).toBe("UPSTREAM_ERROR");
  });
  it("accepts empty finished upstream response only with caveats", async () => {
    const mock = vi.fn<typeof fetch>().mockResolvedValue(response({}));
    const result = await queryOfficialOsv(request, { fetchImpl: mock, now });
    expect(result.status).toBe("COMPLETE");
    expect(result.vulnerabilities).toHaveLength(0);
    expect(result.warnings.join(" ")).toMatch(/not establish/i);
  });
});
