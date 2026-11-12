import { describe, expect, it } from "vitest";
import {
  emptyV2Manifest, defaultV2Controls, type V2Evidence,
  type V2Finding, type V2Scope,
} from "./multisource-v2-contract";
import {
  calculateMultiSourceCyberScoreV2,
  calculateV2RiskContributions,
  parseV2ModelPolicy,
  selectV2ScoreFindings,
  compareV2Scores,
} from "./multisource-v2-score";
import { computeV2Coverage } from "./multisource-v2-coverage";
import {
  sha256V2, v2ModelRegistry, createV2HistoryEntry,
  createV2HistoricalTimeline, reconcileV2History,
  compareV2TimelineToV1, compareV2ModelVersions,
} from "./multisource-v2-history";
const org = "score-v2-tenant-12345";
const at = "2026-11-12T10:00:00.000Z";
const sha = "b".repeat(64);
const controls = defaultV2Controls().filter(c =>
  c.domain === "IDENTITY" && c.id !== "IDENTITY_INACTIVE_ACCOUNTS");
function make() {
  return emptyV2Manifest(org, at, "score-snapshot-12345", controls);
}
function link(controlId: string, index: number) {
  const spec = controls.find(c => c.id === controlId)!;
  const e: V2Evidence = {
    schema: "cyberpilot.multisource.evidence.v2",
    organizationId: org, evidenceId: "evidence-" + index,
    source: "MICROSOFT_365", domain: spec.domain,
    controlId, scope: "tenant-accounts",
    scopeKind: "ORGANIZATION",
    subjectHash: sha, state: "OBSERVED",
    confidence: "HIGH",
    verification: "TECHNICALLY_VERIFIED",
    observedAt: at, checkedAt: at, validUntil: null,
    sourceDigest: sha, sourceReference: "source-v2",
    authority: "provider-observation",
    sourceCoverage: "COMPLETE",
    details: { verified: true },
    rawPersonalDataStored: false,
    providerAccountModified: false,
    customerApprovalInferred: false,
  };
  const s: V2Scope = {
    organizationId: org, source: "MICROSOFT_365",
    domain: spec.domain, scopeKind: "ORGANIZATION",
    scope: "tenant-accounts", expectedSubjects: 2,
    observedSubjects: 2, totalPages: 1, pagesObserved: 1,
    status: "COMPLETE", checkedAt: at,
    validUntil: null, sourceDigest: sha,
    customerTenantAuthenticated: true,
    scopeAuthenticityVerified: true, errors: [],
  };
  return { e, s };
}
function makeFinding(e: V2Evidence, index = 1): V2Finding {
  return {
    schema: "cyberpilot.multisource.finding.v2",
    organizationId: org,
    findingId: "finding-" + index,
    ruleId: "IDENTITY_UNPROTECTED_PRIVILEGE",
    domain: "IDENTITY",
    controlId: e.controlId, scope: e.scope,
    subjectHash: e.subjectHash, source: e.source,
    severity: "HIGH", state: "POTENTIAL_RISK",
    title: "Privileged identity without MFA",
    explanation: "Evidence explicitly observes insufficient MFA.",
    remediation: "Review and require multi-factor authentication.",
    evidenceIds: [e.evidenceId], observedAt: at,
    confidence: "HIGH", autoRemediated: false,
    customerAccepted: false, resolved: false,
  };
}
describe("CyberScore v2 opt-in scoring safety", () => {
  it("never emits numeric score from an empty source", () => {
    const score = calculateMultiSourceCyberScoreV2(make());
    expect(score.score).toBe(null);
    expect(score.status).toBe("UNASSESSABLE");
    expect(score.legacyCyberScoreRecomputed).toBe(false);
    expect(score.eligibleForProductHealthBadge).toBe(false);
  });
  it("produces no numeric score for a single observed control", () => {
    const data = make();
    const row = link(controls[0]!.id, 1);
    data.evidence.push(row.e);
    data.scopes.push(row.s);
    data.sourceDigests.push(sha);
    const score = calculateMultiSourceCyberScoreV2(data);
    expect(score.score).toBe(null);
    expect(score.status).toBe("INSUFFICIENT_COVERAGE");
  });
  it("does not allow lowering minimum verified coverage below 60%", () => {
    expect(() => parseV2ModelPolicy({
      minimumCoveragePercent: 1,
    })).toThrow();
    expect(() => parseV2ModelPolicy({
      acceptFixtureAsCustomerProof: true,
    })).toThrow();
    expect(() => parseV2ModelPolicy({
      requireAuthenticatedSource: false,
    })).toThrow();
  });
  it("never claims customer health even for a complete provider population", () => {
    const data = make();
    controls.forEach((c, i) => {
      const row = link(c.id, i + 1);
      data.evidence.push(row.e);
      data.scopes.push(row.s);
    });
    data.sourceDigests.push(sha);
    const score = calculateMultiSourceCyberScoreV2(data);
    // Only three controls: default minimum is five verified controls.
    expect(score.score).toBe(null);
    expect(score.coveragePercent).toBe(100);
    expect(score.eligibleForProductHealthBadge).toBe(false);
  });
  it("applies uncertainty penalty to eligible partially covered 5-control scoring", () => {
    const trusted = defaultV2Controls().filter(c =>
      c.scope === "ORGANIZATION" &&
      c.acceptedSources.includes("MICROSOFT_365")).slice(0, 5);
    expect(trusted).toHaveLength(5);
    const additional = defaultV2Controls().find(c =>
      c.id === "BACKUP_POLICY")!;
    const manifest = emptyV2Manifest(org, at,
      "eligible-partial-12345", [...trusted, additional]);
    trusted.forEach((control, i) => {
      const pair = link(controls[0]!.id, i + 1);
      manifest.evidence.push({
        ...pair.e, evidenceId: "proof-" + (i + 1),
        controlId: control.id, domain: control.domain,
      });
      manifest.scopes.push({
        ...pair.s, domain: control.domain,
      });
    });
    manifest.sourceDigests = [sha];
    const score = calculateMultiSourceCyberScoreV2(manifest);
    const coverage = computeV2Coverage(manifest);
    expect(coverage.verifiedControls).toBe(5);
    expect(coverage.coveragePercent).toBeLessThan(100);
    expect(score.score).not.toBeNull();
    expect(score.score).toBeLessThan(100);
    expect(score.score).toBe(score.scoreRange.min);
    expect(score.scoreRange.max).toBe(100);
    expect(score.legacyCyberScoreRecomputed).toBe(false);
    expect(score.eligibleForProductHealthBadge).toBe(false);
  });
  it("excludes findings with no verified link", () => {
    const data = make();
    const row = link(controls[0]!.id, 1);
    data.evidence.push(row.e);
    data.scopes.push(row.s);
    data.sourceDigests.push(sha);
    data.findings.push(makeFinding(row.e));
    const results = selectV2ScoreFindings(data,
      computeV2Coverage(data));
    expect(results.accepted).toHaveLength(1);
    expect(results.unsupported).toHaveLength(0);
  });
  it("caps risk contributions and does not double-count duplicate subjects", () => {
    const data = make();
    const row = link(controls[0]!.id, 1);
    data.evidence.push(row.e);
    data.scopes.push(row.s);
    data.sourceDigests.push(sha);
    data.findings.push(makeFinding(row.e, 1));
    data.findings.push({
      ...makeFinding(row.e, 2),
      findingId: "finding-0002",
    });
    const selected = selectV2ScoreFindings(data,
      computeV2Coverage(data));
    expect(selected.accepted).toHaveLength(1);
    expect(selected.duplicateIds).toHaveLength(1);
    const contributions = calculateV2RiskContributions(data,
      computeV2Coverage(data));
    expect(contributions).toHaveLength(1);
    expect(contributions[0]!.appliedPoints).toBeLessThanOrEqual(25);
  });
});
describe("v2 immutable scoring history", () => {
  it("matches SHA-256 reference vectors", () => {
    expect(sha256V2("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256V2("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
  it("allows an unscorable v2 baseline without touching legacy records", () => {
    const entry = createV2HistoryEntry(make());
    const audit = reconcileV2History(org, [entry]);
    expect(audit.valid).toBe(true);
    const timeline = createV2HistoricalTimeline(org, [entry]);
    expect(timeline.numericScores).toBe(0);
    expect(timeline.unscorableSnapshots).toBe(1);
    const legacy = compareV2TimelineToV1(timeline, [{
      id: "legacy-001", score: 94,
      modelVersion: "v1", calculatedAt: at,
    }]);
    expect(legacy.legacyDatabaseWriteCount).toBe(0);
    expect(legacy.legacyScoresRetainedExactly[0]!.score).toBe(94);
    expect(legacy.statisticallyComparable).toBe(false);
  });
  it("rejects a history mutation after the digest was issued", () => {
    const entry = createV2HistoryEntry(make());
    const altered = JSON.parse(JSON.stringify(entry)) as typeof entry;
    altered.score.riskPoints = 99;
    expect(reconcileV2History(org, [altered]).valid).toBe(false);
  });
  it("rejects mixed tenant and wrong history parent", () => {
    const first = createV2HistoryEntry(make());
    const nextManifest = make();
    nextManifest.evaluatedAt = "2026-11-13T10:00:00.000Z";
    nextManifest.snapshotId = "score-snapshot-54321";
    const second = createV2HistoryEntry(nextManifest, first);
    expect(createV2HistoricalTimeline(org,
      [first, second]).revisions).toBe(2);
    expect(reconcileV2History(org, [second]).valid).toBe(false);
  });
  it("refuses implicit numeric equality between v1 and v2", () => {
    expect(compareV2ModelVersions(
      "cyberpilot.v1", "cyberpilot.multisource.v2")
      .comparable).toBe(false);
    expect(v2ModelRegistry().writesLegacyScores).toBe(false);
    expect(v2ModelRegistry().migrationStrategy)
      .toBe("SIDE_BY_SIDE_ONLY");
  });
});
