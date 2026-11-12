import { describe, expect, it } from "vitest";
import { type ExposureOfflineEnvelope,
  assessExposureOffline } from "./exposure-offline-v2";
import { type BaselineSubmission } from "./baseline-questions";
import {
  buildPhase2OfflinePortfolio, verifyPhase2OfflinePortfolio,
  comparePhase2Portfolios, exportPhase2Portfolio,
  type Phase2PortfolioInput,
} from "./exposure-baseline-v2-portfolio";
import {
  assessBaselineOfflineV2,
} from "./baseline-offline-v2";
import {
  buildExposureBaselineV2Bridge,
  verifyExposureBaselineV2Bridge,
} from "./exposure-baseline-v2-bridge";
const org = "combined-small-business-12345";
const at = "2026-11-12T14:00:00.000Z";
function exposure(): ExposureOfflineEnvelope {
  return {
    schema: "cyberpilot.exposure.offline.v2",
    organizationId: org, snapshotId: "exposure-source-12345",
    assessedAt: at, domain: "business.example.com",
    authorization: {
      schema: "cyberpilot.exposure.authorization.v2",
      organizationId: org, domain: "business.example.com",
      purpose: "PASSIVE_ASSESSMENT",
      verificationMethod: "DECLARATION",
      verified: false, verifiedAt: null, expiresAt: null,
      challengeDigest: null, collectorIdentity: "offline-fixture",
      consentRecordId: "offline-consent-12345",
      canPerformActiveScanning: false,
      externalOwnershipIndependentlyVerified: false,
    },
    dns: [{
      id: "spf-source-12345", kind: "SPF", status: "OBSERVED",
      queriedName: "business.example.com",
      records: ["v=spf1 ~all"], collectedAt: at,
      elapsedMs: null, resolver: "fixture",
      observedFromAuthorizedScope: true,
      queriedExternalNames: [],
    }, {
      id: "dmarc-source-12345", kind: "DMARC", status: "OBSERVED",
      queriedName: "_dmarc.business.example.com",
      records: ["v=DMARC1; p=none"],
      collectedAt: at, elapsedMs: null, resolver: "fixture",
      observedFromAuthorizedScope: true,
      queriedExternalNames: [],
    }],
    tls: [], http: [],
    collectionMode: "IMPORTED_PASSIVE_EVIDENCE",
    networkRequestsByEvaluator: 0,
    dynamicLookupsByEvaluator: 0,
    thirdPartyScanningAuthorized: false,
    sourceIsSynthetic: true,
    claimsVerifiedProductionSecurity: false,
  };
}
function baseline(): BaselineSubmission {
  return {
    organizationId: org, questionnaireVersion: 1,
    submittedAt: at, responses: [
      { questionId: "backups", answer: "NO" },
      { questionId: "restore-tests", answer: "UNKNOWN" },
      { questionId: "mfa", answer: "YES",
        evidenceReference: "reference-mfa-12345" },
      { questionId: "incident-plan", answer: "PARTIAL" },
    ],
  };
}
function input(): Phase2PortfolioInput {
  return {
    schema: "cyberpilot.phase2.portfolio.input.v1",
    organizationId: org, snapshotId: "combined-portfolio-12345",
    evaluatedAt: at, actorId: "operator-offline-12345",
    exposure: [exposure()], baseline: baseline(),
    sourceMode: "OFFLINE_ONLY",
    liveNetworkRequestsAllowed: false,
    oauthTokensProvided: false,
    authorizedLiveTenantClaimed: false,
    maximumActions: 50,
  };
}
describe("Offline Exposure and Baseline in the v2 core", () => {
  it("produces an M365-free portfolio from SPF, DMARC and company declarations", () => {
    const report = buildPhase2OfflinePortfolio(input());
    expect(report.sources).toHaveLength(2);
    expect(report.overview.noM365Required).toBe(true);
    expect(report.overview.score).toBeNull();
    expect(report.overview.technicalCoveragePercent).toBe(0);
    expect(report.priorities.length).toBeGreaterThan(0);
    expect(report.historicalCyberScoreUpdated).toBe(false);
    expect(report.customerApprovedDeployment).toBe(false);
    expect(verifyPhase2OfflinePortfolio(report).valid).toBe(true);
  });
  it("keeps all imported v2 evidence unverified for scoring", () => {
    const report = buildPhase2OfflinePortfolio(input());
    expect(report.bridge.score.score).toBeNull();
    expect(report.bridge.coverage.verifiedControls).toBe(0);
    expect(report.bridge.manifest.evidence.every(x =>
      x.verification !== "TECHNICALLY_VERIFIED")).toBe(true);
    expect(report.bridge.manifest.evidence.some(x =>
      x.source === "EXPOSURE")).toBe(true);
    expect(report.bridge.manifest.evidence.some(x =>
      x.source === "BASELINE")).toBe(true);
    expect(report.bridge.scoredFindings).toBe(0);
  });
  it("supports a Baseline-only organization with unknown technical coverage", () => {
    const data = input();
    data.exposure = [];
    const report = buildPhase2OfflinePortfolio(data);
    expect(report.sources).toHaveLength(1);
    expect(report.exposureReports).toEqual([]);
    expect(report.overview.score).toBeNull();
    expect(report.baselineReport).not.toBeNull();
  });
  it("supports Exposure-only without converting passive DNS to LIVE provenance", () => {
    const data = input();
    data.baseline = null;
    const report = buildPhase2OfflinePortfolio(data);
    expect(report.sources).toHaveLength(1);
    expect(report.overview.score).toBeNull();
    expect(report.baselineReport).toBeNull();
  });
  it("rejects cross-tenant Exposure source before constructing a portfolio", () => {
    const data = input();
    data.exposure[0]!.organizationId = "foreign-tenant-12345";
    expect(() => buildPhase2OfflinePortfolio(data)).toThrow();
  });
  it("rejects cross-tenant Baseline source before constructing a portfolio", () => {
    const data = input();
    data.baseline!.organizationId = "foreign-tenant-12345";
    expect(() => buildPhase2OfflinePortfolio(data)).toThrow();
  });
  it("prevents proposed active network requests", () => {
    const data = input();
    (data as unknown as Record<string, unknown>)
      .liveNetworkRequestsAllowed = true;
    expect(() => buildPhase2OfflinePortfolio(data)).toThrow();
  });
  it("rejects unauthorized simulated OAuth approval", () => {
    const data = input();
    (data as unknown as Record<string, unknown>)
      .authorizedLiveTenantClaimed = true;
    expect(() => buildPhase2OfflinePortfolio(data)).toThrow();
  });
  it("emits neutral v2 bridge with explicit missing control coverage", () => {
    const exposureSource = assessExposureOffline(exposure());
    const baselineSource = assessBaselineOfflineV2(baseline(), {
      organizationId: org, snapshotId: "baseline-snap-12345",
      evaluatedAt: at, completedBy: "offline-actor-12345",
      notePolicy: "DISCARD_CONTENT",
      referencePolicy: "OPAQUE_IDENTIFIERS_ONLY",
      maxActions: 50,
    });
    const bridge = buildExposureBaselineV2Bridge({
      organizationId: org, snapshotId: "bridge-snap-12345",
      evaluatedAt: at,
    }, [exposureSource], baselineSource);
    expect(verifyExposureBaselineV2Bridge(bridge).valid).toBe(true);
    expect(bridge.scoredFindings).toBe(0);
    expect(bridge.pendingReviewControls).toBeGreaterThan(10);
  });
  it("offers exportable JSON and Markdown without security claims", () => {
    const report = buildPhase2OfflinePortfolio(input());
    for (const format of ["JSON", "CSV", "MARKDOWN"] as const) {
      const artifact = exportPhase2Portfolio(report, format);
      expect(artifact.output.length).toBeGreaterThan(100);
      expect(artifact.certificationProvided).toBe(false);
      expect(artifact.externalNetworkRequests).toBe(0);
      expect(artifact.legacyCyberScoreWrites).toBe(0);
    }
  });
  it("prevents trend comparisons between separate organizations", () => {
    const first = buildPhase2OfflinePortfolio(input());
    const other = input();
    other.organizationId = "foreign-tenant-12345";
    other.exposure[0]!.organizationId = other.organizationId;
    other.exposure[0]!.authorization.organizationId = other.organizationId;
    other.baseline!.organizationId = other.organizationId;
    other.snapshotId = "other-portfolio-12345";
    other.evaluatedAt = "2026-11-13T14:00:00.000Z";
    const second = buildPhase2OfflinePortfolio(other);
    expect(() => comparePhase2Portfolios(first, second)).toThrow();
  });
});
