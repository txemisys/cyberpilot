import { describe, expect, it } from "vitest";
import {
  buildOsvCandidateReport, correlateOsvRow,
  osvPackageKey, parseOsvAffected, parseOsvFeed,
  parseOsvRecord, parsePackageBindings, summarizeOsvCandidates,
} from "./assets-osv-correlation";
import {
  compareOsvCandidateReports, parseOsvRequest,
} from "./assets-osv-service";
const now = new Date("2026-11-05T12:00:00.000Z");
const rawFeed = {
  sourceLabel: "Synthetic OSV fixture",
  sourceVersion: "fixture-1",
  retrievedAt: "2026-11-04T12:00:00.000Z",
  records: [
    {
      id: "CVE-2026-10001",
      modified: "2026-11-03T12:00:00Z",
      aliases: [],
      affected: [
        { package: { ecosystem: "npm", name: "example-package" },
          versions: ["1.2.3"] },
      ],
    },
    {
      id: "CVE-2026-10002",
      modified: "2026-11-03T12:00:00Z",
      affected: [
        { package: { ecosystem: "npm", name: "example-package" },
          ranges: [
            { type: "SEMVER", events: [
              { introduced: "0" }, { fixed: "1.2.4" },
            ] },
          ],
        },
      ],
    },
    {
      id: "CVE-2026-10003",
      modified: "2026-11-03T12:00:00Z",
      withdrawn: "2026-11-03T15:00:00Z",
      affected: [
        { package: { ecosystem: "npm", name: "example-package" },
          versions: ["1.2.3"] },
      ],
    },
  ],
};
const bindings = [{
  inventoryProduct: "Example Package",
  ecosystem: "npm", packageName: "example-package",
  expectedPurl: null,
}];
const row = {
  externalId: "asset-12345", softwareName: "Example Package",
  softwareVersion: "1.2.3", versionStatus: "EXACT",
  normalizedProductKey: "example package",
  observedAt: now, sourceRow: 2,
};
const reportQuery = { offset: 0, limit: 50 };
describe("OSV export input validation", () => {
  it("accepts OSV records without relying on network calls", () => {
    const parsed = parseOsvFeed(rawFeed);
    expect(parsed.recordCount).toBe(3);
    expect(parsed.withdrawnCount).toBe(1);
    expect(parsed.rangeOnlyCount).toBe(1);
    expect(parsed.source).toBe("USER_SUPPLIED_OSV_EXPORT");
    expect(parsed.digest).toMatch(/^[a-f0-9]{64}$/);
  });
  it("normalizes package keys without dropping ecosystem identity", () => {
    expect(osvPackageKey("npm", " Example Package™ "))
      .toBe(osvPackageKey("NPM", "example package"));
    expect(osvPackageKey("PyPI", "example-package"))
      .not.toBe(osvPackageKey("npm", "example-package"));
  });
  it("rejects missing advisory identity and invalid timestamps", () => {
    expect(() => parseOsvRecord({
      ...rawFeed.records[0], id: "bad id",
    }, 0)).toThrow();
    expect(() => parseOsvRecord({
      ...rawFeed.records[0], modified: "2026-02-30T12:00:00Z",
    }, 0)).toThrow();
  });
  it("rejects duplicate records and duplicate aliases", () => {
    expect(() => parseOsvFeed({
      ...rawFeed, records: [
        rawFeed.records[0], rawFeed.records[0],
      ],
    })).toThrow();
    expect(() => parseOsvRecord({
      ...rawFeed.records[0], aliases: ["CVE-2026-10000", "CVE-2026-10000"],
    }, 0)).toThrow();
  });
  it("accepts exact enumerated versions and bounded ranges", () => {
    const affected = parseOsvAffected({
      package: { ecosystem: "npm", name: "example-package" },
      versions: ["1.2.3"],
      ranges: [
        { type: "SEMVER", events: [
          { introduced: "0" }, { fixed: "2.0.0" },
        ] },
      ],
    }, "affected");
    expect(affected.versions).toEqual(["1.2.3"]);
    expect(affected.rangesPresent).toBe(true);
  });
  it.each([
    {
      package: { ecosystem: "npm", name: "example-package" },
      versions: ["latest"],
    },
    {
      package: { ecosystem: "npm", name: "example-package" },
      versions: ["1.2.3", "1.2.3"],
    },
    {
      package: { ecosystem: "npm", name: "example-package" },
      ranges: [{ type: "OTHER", events: [{ introduced: "0" }] }],
    },
    {
      package: { ecosystem: "npm", name: "example-package" },
      ranges: [{ type: "SEMVER", events: [
        { introduced: "0", fixed: "2.0.0" },
      ] }],
    },
    {
      package: { ecosystem: "npm", name: "example-package" },
    },
  ])("rejects malformed or unsupported affected entries", value => {
    expect(() => parseOsvAffected(value, "test")).toThrow();
  });
  it("rejects missing or ambiguous product bindings", () => {
    expect(() => parsePackageBindings([
      ...bindings, ...bindings,
    ])).toThrow();
    expect(() => parsePackageBindings([{
      ...bindings[0], expectedPurl: "https://invalid.example",
    }])).toThrow();
    expect(() => parsePackageBindings([{ ecosystem: "npm" }])).toThrow();
  });
  it("rejects overly large record collections", () => {
    expect(() => parseOsvFeed({
      ...rawFeed, records: Array(501).fill(rawFeed.records[0]),
    })).toThrow();
  });
  it("rejects nonvalidated correlation request envelopes", () => {
    expect(() => parseOsvRequest({
      importId: "import-12345", feed: rawFeed,
    })).toThrow();
    expect(() => parseOsvRequest({
      importId: "import-12345", feed: rawFeed,
      packageBindings: bindings, limit: 0,
    })).toThrow();
    expect(() => parseOsvRequest({
      importId: "import-12345", feed: rawFeed,
      packageBindings: bindings, unrecognized: true,
    })).toThrow();
  });
});
describe("conservative OSV candidate correlation", () => {
  const feed = parseOsvFeed(rawFeed);
  const parsedBindings = parsePackageBindings(bindings);
  it("produces a possible match only when name, ecosystem and version agree", () => {
    const candidate = correlateOsvRow(row, feed, parsedBindings);
    expect(candidate.category).toBe("EXACT_AFFECTED_VERSION");
    expect(candidate.possibleAdvisoryIds).toEqual(["CVE-2026-10001"]);
    expect(candidate.withdrawnIds).toEqual(["CVE-2026-10003"]);
    expect(candidate.unresolvedRangeIds).toEqual(["CVE-2026-10002"]);
    expect(candidate.certainty).toBe("DECLARED_EXACT_ASSOCIATION");
  });
  it("does not match ecosystem-mismatched package", () => {
    const candidate = correlateOsvRow(row, feed, [{
      ...parsedBindings[0]!, ecosystem: "PyPI",
    }]);
    expect(candidate.possibleAdvisoryIds).toEqual([]);
    expect(candidate.category).toBe("NO_EXACT_VERSION_MATCH");
  });
  it("does not infer binding from a similar product label", () => {
    const candidate = correlateOsvRow({
      ...row, softwareName: "Similar Package",
      normalizedProductKey: "similar package",
    }, feed, parsedBindings);
    expect(candidate.category).toBe("UNMAPPED_PRODUCT");
  });
  it("does not infer affected versions from ranges", () => {
    const candidate = correlateOsvRow({
      ...row, softwareVersion: "1.0.0",
    }, feed, parsedBindings);
    expect(candidate.category).toBe("RANGES_UNEVALUATED");
    expect(candidate.possibleAdvisoryIds).toEqual([]);
  });
  it("does not call unknown or ambiguous versions safe", () => {
    const candidate = correlateOsvRow({
      ...row, softwareVersion: "latest",
      versionStatus: "AMBIGUOUS",
    }, feed, parsedBindings);
    expect(candidate.category).toBe("UNKNOWN_VERSION");
  });
  it("treats withdrawn-only advisories as withdrawn", () => {
    const withdrawnOnly = parseOsvFeed({
      ...rawFeed, records: [rawFeed.records[2]],
    });
    const candidate = correlateOsvRow(row, withdrawnOnly, parsedBindings);
    expect(candidate.category).toBe("WITHDRAWN_RECORD");
    expect(candidate.possibleAdvisoryIds).toHaveLength(0);
  });
  it("does not match another version enumerated by a related record", () => {
    const result = correlateOsvRow({
      ...row, softwareVersion: "5.0.0",
    }, feed, parsedBindings);
    expect(result.category).toBe("RANGES_UNEVALUATED");
    expect(result.possibleAdvisoryIds).toEqual([]);
  });
  it("requires equality of package URL when explicit binding provides one", () => {
    const result = correlateOsvRow(row, feed, [{
      ...parsedBindings[0]!, expectedPurl: "pkg:npm/example-package",
    }]);
    expect(result.possibleAdvisoryIds).toEqual([]);
  });
  it("computes deterministic digests for identical feed and inventory", () => {
    const first = correlateOsvRow(row, feed, parsedBindings);
    const second = correlateOsvRow(row, feed, parsedBindings);
    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.feedDigest).toBe(feed.digest);
  });
  it("aggregates all rows and never equates UNKNOWN to NO_MATCH", () => {
    const rows = [
      correlateOsvRow(row, feed, parsedBindings),
      correlateOsvRow({
        ...row, externalId: "asset-22222",
        softwareName: "Unmapped", normalizedProductKey: "unmapped",
      }, feed, parsedBindings),
      correlateOsvRow({
        ...row, externalId: "asset-33333", softwareVersion: null,
        versionStatus: "MISSING",
      }, feed, parsedBindings),
    ];
    expect(summarizeOsvCandidates(rows)).toMatchObject({
      totalRows: 3, mappedRows: 2, unmappedRows: 1,
      unknownVersions: 1, possibleAssociations: 1,
    });
  });
  it("marks paginated report as incomplete", () => {
    const result = buildOsvCandidateReport(
      "org-12345", "import-12345",
      [row, { ...row, externalId: "asset-22222" }],
      feed, parsedBindings, 0, 1, now,
    );
    expect(result.summary.totalRows).toBe(2);
    expect(result.candidates).toHaveLength(1);
    expect(result.hasMore).toBe(true);
    expect(result.complete).toBe(false);
    expect(result.warnings.join(" ")).toMatch(/do not establish/i);
  });
  it("compares only complete OSV candidate reports in one tenant", () => {
    const prior = buildOsvCandidateReport("org-12345", "import-12345",
      [row], feed, parsedBindings, 0, 50, now);
    const nextFeed = parseOsvFeed({
      ...rawFeed, sourceVersion: "fixture-2",
      records: [rawFeed.records[1]],
    });
    const next = buildOsvCandidateReport("org-12345", "import-12345",
      [row], nextFeed, parsedBindings, 0, 50, now);
    expect(compareOsvCandidateReports(prior, next)[0]?.category)
      .toBe("CHANGED_INTERPRETATION");
    expect(() => compareOsvCandidateReports(prior, {
      ...next, complete: false,
    })).toThrow();
    expect(() => compareOsvCandidateReports(prior, {
      ...next, organizationId: "org-foreign",
    })).toThrow();
  });
  it("refuses to infer remediation from omission of an advisory", () => {
    const prior = buildOsvCandidateReport("org-12345", "import-12345",
      [row], feed, parsedBindings, 0, 50, now);
    const emptyMatch = parseOsvFeed({
      ...rawFeed, sourceVersion: "fixture-3",
      records: [{
        id: "CVE-2026-10004",
        modified: "2026-11-04T12:00:00Z",
        affected: [{
          package: { ecosystem: "npm", name: "different" },
          versions: ["1.2.3"],
        }],
      }],
    });
    const next = buildOsvCandidateReport("org-12345", "import-12345",
      [row], emptyMatch, parsedBindings, 0, 50, now);
    expect(compareOsvCandidateReports(prior, next)[0]?.explanation)
      .toMatch(/inspect upstream records|not proof of remediation/i);
  });
});
