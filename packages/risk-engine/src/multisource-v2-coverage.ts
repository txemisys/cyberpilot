import {
  type V2ControlSpec, type V2Coverage,
  type V2CoverageRow, type V2Domain,
  type V2DomainCoverage, type V2Evidence,
  type V2Manifest, type V2Scope, type V2Source,
  type V2Status, validateV2Manifest,
  validV2Time, v2StableKey,
} from "./multisource-v2-contract";

/**
 * Coverage is assessed per required CONTROL and scope, not merely by
 * counting returned rows. A complete Directory fixture proves only
 * local pagination, never customer tenant-wide scope.
 */
export type V2ScopeEvaluation = {
  source: V2Source;
  domain: V2Domain;
  scope: string;
  expected: number | null;
  observed: number | null;
  eligible: boolean;
  fresh: boolean;
  complete: boolean;
  authRequired: boolean;
  verifiedAuthenticity: boolean;
  status: V2Scope["status"];
  limitations: string[];
};
export type V2Conflict = {
  code: "CROSS_SOURCE_DISAGREEMENT" |
    "DUPLICATE_OBSERVATION" |
    "DIVERGENT_SCOPE" | "EXPIRED_EVIDENCE" |
    "VERIFICATION_INSUFFICIENT" |
    "INCOMPLETE_POPULATION";
  controlId: string;
  subjectHash: string;
  evidenceIds: string[];
  sources: V2Source[];
  action: "REVIEW" | "WAIT_FOR_FRESH_SOURCE" |
    "REQUEST_SCOPE_EVIDENCE";
  resolvedAutomatically: false;
  canAssertSecurity: false;
};
export type V2DeduplicatedEvidence = {
  organizationId: string;
  evidence: V2Evidence[];
  supersededEvidenceIds: string[];
  competingEvidenceIds: string[];
  droppedInvalidRows: number;
  inferredHealth: false;
  sourceClass: "TENANT_BOUND_EVIDENCE";
};
const live = new Set<V2Source>([
  "MICROSOFT_365", "GOOGLE_WORKSPACE", "EXPOSURE",
]);
function isFiniteDate(value: string | null) {
  return value !== null && validV2Time(value);
}
function within(value: string | null, at: string,
  days: number) {
  if (value === null || !isFiniteDate(value)) return false;
  const delta = Date.parse(at) - Date.parse(value);
  return delta >= 0 && delta <= days * 86400000;
}
function effectiveDate(item: V2Evidence) {
  return item.observedAt ?? item.checkedAt;
}
function eligibleScope(scope: V2Scope, at: string) {
  if (scope.status !== "COMPLETE") return false;
  if (scope.validUntil !== null && scope.validUntil < at)
    return false;
  if (scope.checkedAt > at) return false;
  if (scope.expectedSubjects === null ||
      scope.observedSubjects === null ||
      scope.observedSubjects < scope.expectedSubjects)
    return false;
  if (scope.totalPages !== null &&
      scope.pagesObserved !== scope.totalPages)
    return false;
  return true;
}
export function summarizeV2SourceScopes(
  manifest: V2Manifest,
): V2ScopeEvaluation[] {
  const at = manifest.evaluatedAt;
  return manifest.scopes.map(scope => {
    const fresh = validV2Time(at) &&
      within(scope.checkedAt, at, 365) &&
      (scope.validUntil === null || scope.validUntil >= at);
    const complete = eligibleScope(scope, at) && fresh;
    const limitations: string[] = [];
    if (scope.status === "PERMISSION_DENIED")
      limitations.push("Source permission denied.");
    if (scope.status === "ERROR")
      limitations.push("Source collection failed.");
    if (scope.status === "UNASSESSED")
      limitations.push("Provider or scope not evaluated.");
    if (scope.status === "PARTIAL")
      limitations.push("Partial collection cannot prove full population.");
    if (scope.expectedSubjects === null ||
        scope.observedSubjects === null)
      limitations.push("Population size is unknown.");
    if (scope.totalPages !== null &&
        scope.pagesObserved !== scope.totalPages)
      limitations.push("Provider pagination is incomplete.");
    if (!fresh) limitations.push("Source scope is stale.");
    if (live.has(scope.source) &&
        !scope.customerTenantAuthenticated)
      limitations.push("No real tenant authentication proven.");
    if (!scope.scopeAuthenticityVerified)
      limitations.push("Scope authenticity not independently verified.");
    return {
      source: scope.source, domain: scope.domain,
      scope: scope.scope, expected: scope.expectedSubjects,
      observed: scope.observedSubjects,
      eligible: complete &&
        (!live.has(scope.source) ||
         scope.customerTenantAuthenticated),
      fresh, complete,
      authRequired: live.has(scope.source),
      verifiedAuthenticity: scope.scopeAuthenticityVerified,
      status: scope.status, limitations,
    };
  });
}
function scopeMatches(item: V2Evidence, scope: V2Scope) {
  if (item.organizationId !== scope.organizationId ||
      item.source !== scope.source ||
      item.domain !== scope.domain ||
      item.scope !== scope.scope)
    return false;
  if (scope.scopeKind !== item.scopeKind)
    return false;
  if (scope.sourceDigest !== item.sourceDigest)
    return false;
  return true;
}
function canScore(
  item: V2Evidence, control: V2ControlSpec,
  scope: V2Scope, at: string,
) {
  if (item.state !== "OBSERVED" ||
      item.verification === "SYNTHETIC_FIXTURE" ||
      item.verification === "NOT_VERIFIED")
    return false;
  if (control.requiredVerification === "TECHNICAL" &&
      item.verification !== "TECHNICALLY_VERIFIED")
    return false;
  if (!within(effectiveDate(item), at, control.maxAgeDays))
    return false;
  if (item.validUntil !== null && item.validUntil < at)
    return false;
  if (item.sourceCoverage !== "COMPLETE")
    return false;
  if (!eligibleScope(scope, at) ||
      !scope.scopeAuthenticityVerified)
    return false;
  if (live.has(item.source) &&
      !scope.customerTenantAuthenticated)
    return false;
  if (item.confidence === "UNKNOWN")
    return false;
  return true;
}
function rank(item: V2Evidence) {
  const verified = item.verification === "TECHNICALLY_VERIFIED" ?
    4 : item.verification === "OPERATOR_DECLARED" ?
      2 : item.verification === "SYNTHETIC_FIXTURE" ? 1 : 0;
  const state = item.state === "OBSERVED" ? 4 :
    item.state === "DECLARED" ? 2 :
      item.state === "UNKNOWN" ? 1 : 0;
  const fresh = Date.parse(item.observedAt ?? item.checkedAt);
  return { verified, state, fresh };
}
export function deduplicateV2Evidence(
  manifest: V2Manifest,
): V2DeduplicatedEvidence {
  const validation = validateV2Manifest(manifest);
  if (!validation.valid)
    throw new Error("Cannot deduplicate invalid or cross-tenant v2 evidence.");
  const groups = new Map<string, V2Evidence[]>();
  for (const item of manifest.evidence) {
    const key = v2StableKey(
      item.organizationId, item.source, item.domain,
      item.controlId, item.scopeKind, item.scope,
      item.subjectHash,
    );
    const previous = groups.get(key) ?? [];
    previous.push(item);
    groups.set(key, previous);
  }
  const supersededEvidenceIds: string[] = [];
  const competingEvidenceIds: string[] = [];
  const selected: V2Evidence[] = [];
  for (const items of groups.values()) {
    const sorted = [...items].sort((a, b) => {
      const left = rank(a), right = rank(b);
      return right.verified - left.verified ||
        right.state - left.state ||
        right.fresh - left.fresh ||
        a.evidenceId.localeCompare(b.evidenceId);
    });
    const chosen = sorted[0]!;
    selected.push(chosen);
    for (const dropped of sorted.slice(1)) {
      if (dropped.state !== chosen.state &&
          dropped.observedAt === chosen.observedAt)
        competingEvidenceIds.push(dropped.evidenceId);
      else supersededEvidenceIds.push(dropped.evidenceId);
    }
  }
  return {
    organizationId: manifest.organizationId,
    evidence: selected.sort((a, b) =>
      a.controlId.localeCompare(b.controlId) ||
      a.scope.localeCompare(b.scope) ||
      a.evidenceId.localeCompare(b.evidenceId)),
    supersededEvidenceIds, competingEvidenceIds,
    droppedInvalidRows: 0, inferredHealth: false,
    sourceClass: "TENANT_BOUND_EVIDENCE",
  };
}
export function detectV2EvidenceConflicts(
  manifest: V2Manifest,
): V2Conflict[] {
  const validation = validateV2Manifest(manifest);
  if (!validation.valid)
    throw new Error("Cannot inspect invalid v2 evidence.");
  const result: V2Conflict[] = [];
  const groups = new Map<string, V2Evidence[]>();
  for (const item of manifest.evidence) {
    const key = v2StableKey(
      item.organizationId, item.domain,
      item.controlId, item.scope, item.subjectHash,
    );
    groups.set(key, [...groups.get(key) ?? [], item]);
  }
  for (const entries of groups.values()) {
    const states = new Set(entries.map(x => x.state));
    const sources = [...new Set(entries.map(x => x.source))];
    const verified = entries.filter(x =>
      x.state === "OBSERVED" &&
      x.verification === "TECHNICALLY_VERIFIED");
    const disagree = states.size > 1 && verified.length > 0;
    const contradictoryDetails = verified.length > 1 &&
      new Set(verified.map(x =>
        JSON.stringify(Object.entries(x.details).sort())))
        .size > 1;
    if (disagree || contradictoryDetails)
      result.push({
        code: "CROSS_SOURCE_DISAGREEMENT",
        controlId: entries[0]!.controlId,
        subjectHash: entries[0]!.subjectHash,
        evidenceIds: entries.map(x => x.evidenceId),
        sources, action: "REVIEW",
        resolvedAutomatically: false,
        canAssertSecurity: false,
      });
  }
  for (const item of manifest.evidence) {
    const control = manifest.expectedControls.find(c =>
      c.id === item.controlId);
    if (!control) continue;
    if (!within(effectiveDate(item), manifest.evaluatedAt,
      control.maxAgeDays))
      result.push({
        code: "EXPIRED_EVIDENCE",
        controlId: item.controlId,
        subjectHash: item.subjectHash,
        evidenceIds: [item.evidenceId], sources: [item.source],
        action: "WAIT_FOR_FRESH_SOURCE",
        resolvedAutomatically: false,
        canAssertSecurity: false,
      });
    if (item.state === "OBSERVED" &&
        item.verification !== "TECHNICALLY_VERIFIED" &&
        control.requiredVerification === "TECHNICAL")
      result.push({
        code: "VERIFICATION_INSUFFICIENT",
        controlId: item.controlId,
        subjectHash: item.subjectHash,
        evidenceIds: [item.evidenceId], sources: [item.source],
        action: "REQUEST_SCOPE_EVIDENCE",
        resolvedAutomatically: false,
        canAssertSecurity: false,
      });
  }
  return result.sort((a, b) =>
    a.controlId.localeCompare(b.controlId) ||
    a.code.localeCompare(b.code));
}
function resolveV2Control(
  control: V2ControlSpec,
  manifest: V2Manifest,
  conflicts: V2Conflict[],
): V2CoverageRow {
  const evidence = manifest.evidence.filter(item =>
    item.controlId === control.id &&
    item.domain === control.domain &&
    item.scopeKind === control.scope &&
    control.acceptedSources.includes(item.source));
  const conflicting = conflicts.some(item =>
    item.controlId === control.id &&
    item.code === "CROSS_SOURCE_DISAGREEMENT");
  const scopes = evidence.flatMap(item =>
    manifest.scopes.filter(scope => scopeMatches(item, scope))
      .map(scope => ({ item, scope })));
  const eligible = scopes.filter(({ item, scope }) =>
    canScore(item, control, scope, manifest.evaluatedAt));
  const fresh = evidence.some(item =>
    within(effectiveDate(item), manifest.evaluatedAt,
      control.maxAgeDays));
  const stale = evidence.length > 0 && !fresh;
  const hasError = evidence.some(item => item.state === "ERROR");
  const observed = evidence.some(item => item.state === "OBSERVED");
  const declared = evidence.some(item => item.state === "DECLARED");
  const unknown = evidence.some(item => item.state === "UNKNOWN");
  const status: V2Status = conflicting ? "CONFLICT" :
    stale ? "STALE" : hasError ? "ERROR" :
    eligible.length ? "OBSERVED" :
    declared ? "DECLARED" : observed || unknown ?
      "UNKNOWN" : "UNKNOWN";
  const selectedEvidence = eligible.length ?
    eligible.map(x => x.item) : evidence;
  const unique = (values: string[]) => [...new Set(values)];
  const sorted = [...selectedEvidence].sort((a, b) =>
    b.checkedAt.localeCompare(a.checkedAt) ||
    a.evidenceId.localeCompare(b.evidenceId));
  const highest = sorted[0] ?? null;
  const unavailability: string[] = [];
  if (evidence.length === 0)
    unavailability.push("No evidence for this required control.");
  if (declared && eligible.length === 0)
    unavailability.push("Declaration does not prove technical posture.");
  if (stale) unavailability.push("All observations are stale.");
  if (hasError) unavailability.push("Provider returned an error.");
  if (conflicting)
    unavailability.push("Sources disagree; manual reconciliation needed.");
  if (scopes.length === 0 && evidence.length)
    unavailability.push("No matching scope proof for evidence.");
  if (scopes.some(({ scope }) => !eligibleScope(scope,
    manifest.evaluatedAt)))
    unavailability.push("Incomplete source population or pagination.");
  if (scopes.some(({ scope }) => live.has(scope.source) &&
    !scope.customerTenantAuthenticated))
    unavailability.push("No authenticated live provider.");
  const findings = manifest.findings.filter(f =>
    f.controlId === control.id);
  return {
    controlId: control.id, domain: control.domain,
    scopeKind: control.scope, weight: control.weight,
    applicability: control.applicability,
    requirement: control.requiredVerification, status,
    sourceIds: [...new Set(evidence.map(e => e.source))],
    evidenceIds: unique(evidence.map(e => e.evidenceId)),
    verifiedEvidenceIds: conflicting ? [] :
      unique(eligible.map(x => x.item.evidenceId)),
    missingSources: control.acceptedSources.filter(s =>
      !evidence.some(e => e.source === s)),
    checkedAt: highest?.checkedAt ?? null,
    observedAt: highest?.observedAt ?? null,
    scope: highest?.scope ?? "UNASSESSED",
    scopeComplete: eligible.length > 0 && !conflicting,
    evidenceFresh: fresh,
    authenticatedLiveEvidence: eligible.some(x =>
      live.has(x.item.source) &&
      x.scope.customerTenantAuthenticated),
    verifiedForScoring: eligible.length > 0 &&
      !conflicting && !hasError,
    findings: findings.length,
    knownRisks: findings.filter(f =>
      f.state === "POTENTIAL_RISK").length,
    uncertainty: unavailability,
    issues: conflicts.filter(c =>
      c.controlId === control.id).map(c => c.code),
  };
}
export function computeV2ControlCoverage(
  manifest: V2Manifest,
): V2CoverageRow[] {
  const checked = validateV2Manifest(manifest);
  if (!checked.valid)
    throw new Error("Invalid multi-source manifest; coverage denied.");
  const conflicts = detectV2EvidenceConflicts(manifest);
  return manifest.expectedControls.map(control =>
    resolveV2Control(control, manifest, conflicts));
}
function buildDomain(
  domain: V2Domain, rows: V2CoverageRow[],
): V2DomainCoverage {
  const expected = rows.filter(x => x.domain === domain &&
    x.applicability === "REQUIRED");
  const sum = (predicate: (row: V2CoverageRow) => boolean) =>
    expected.filter(predicate).length;
  const weightTotal = expected.reduce((sum, item) =>
    sum + item.weight, 0);
  const verifiedWeight = expected.reduce((sum, row) =>
    sum + (row.verifiedForScoring ? row.weight : 0), 0);
  const sources = [...new Set(expected.flatMap(x => x.sourceIds))];
  const missing = expected.filter(x =>
    !x.verifiedForScoring).map(x => x.controlId);
  const coveragePercent = weightTotal === 0 ? 0 :
    Math.round(100 * verifiedWeight / weightTotal);
  const verified = expected.length > 0 &&
    missing.length === 0;
  const limitations: string[] = [];
  if (!expected.length)
    limitations.push("No required controls configured for this domain.");
  if (missing.length)
    limitations.push("Required controls remain unknown, partial, stale or conflicted.");
  if (expected.some(x => x.status === "DECLARED"))
    limitations.push("Declarations do not certify technical security.");
  if (expected.some(x => x.status === "ERROR"))
    limitations.push("Source errors prevent full domain coverage.");
  return {
    domain, expectedControls: expected.length,
    observedControls: sum(x => x.status === "OBSERVED"),
    declaredControls: sum(x => x.status === "DECLARED"),
    unknownControls: sum(x => x.status === "UNKNOWN"),
    errorControls: sum(x => x.status === "ERROR"),
    staleControls: sum(x => x.status === "STALE"),
    conflictControls: sum(x => x.status === "CONFLICT"),
    weightTotal, verifiedWeight, coveragePercent,
    verified, healthyAllowed: false, sources,
    missingControls: missing, limitations,
  };
}
export function computeV2Coverage(
  manifest: V2Manifest,
): V2Coverage {
  const controls = computeV2ControlCoverage(manifest);
  const required = controls.filter(x =>
    x.applicability === "REQUIRED");
  const domains = [...new Set(manifest.expectedDomains)]
    .map(domain => buildDomain(domain, controls));
  const requiredWeight = required.reduce((sum, row) =>
    sum + row.weight, 0);
  const verifiedWeight = required.reduce((sum, row) =>
    sum + (row.verifiedForScoring ? row.weight : 0), 0);
  const partialWeight = required.reduce((sum, row) =>
    sum + (row.status === "DECLARED" ? row.weight : 0), 0);
  const unknownWeight = requiredWeight - verifiedWeight;
  const coveragePercent = requiredWeight === 0 ? 0 :
    Math.round(100 * verifiedWeight / requiredWeight);
  const sources = [...new Set(manifest.evidence.map(e => e.source))];
  const liveProviderAuthenticated = manifest.scopes.some(s =>
    live.has(s.source) && s.customerTenantAuthenticated &&
    s.scopeAuthenticityVerified);
  const fullTenantCoverageProven = required.length > 0 &&
    required.every(c => c.verifiedForScoring &&
      c.scopeComplete) && liveProviderAuthenticated;
  const warnings: string[] = [];
  if (coveragePercent < 100)
    warnings.push("Coverage is incomplete; unknown cannot be scored as safe.");
  if (!liveProviderAuthenticated)
    warnings.push("No authenticated LIVE source; avoid tenant security assertions.");
  if (manifest.evidence.some(x =>
    x.verification === "SYNTHETIC_FIXTURE"))
    warnings.push("A local fixture is not independent provider evidence.");
  if (manifest.evidence.some(x => x.state === "DECLARED"))
    warnings.push("Declared controls require explicit provenance.");
  if (required.length === 0)
    warnings.push("No required controls; scoring is not meaningful.");
  const healthClaimPermitted = false;
  return {
    schema: "cyberpilot.multisource.coverage.v2",
    organizationId: manifest.organizationId,
    evaluatedAt: manifest.evaluatedAt,
    modelId: "cyberpilot.multisource.v2",
    controls, domains,
    requiredWeight, verifiedWeight, partialWeight,
    unknownWeight, coveragePercent,
    totalControls: required.length,
    verifiedControls: required.filter(x =>
      x.verifiedForScoring).length,
    missingControls: required.filter(x =>
      !x.verifiedForScoring).length,
    conflicts: required.filter(x =>
      x.status === "CONFLICT").length,
    stale: required.filter(x => x.status === "STALE").length,
    errors: required.filter(x => x.status === "ERROR").length,
    sources, liveProviderAuthenticated,
    syntheticDataPresent: manifest.evidence.some(x =>
      x.verification === "SYNTHETIC_FIXTURE"),
    fullTenantCoverageProven,
    sourceEquivalenceProven: false,
    canonicalV1ScoreChanged: false,
    healthClaimPermitted, warnings,
  };
}
export function coverageV2BySource(
  coverage: V2Coverage,
) {
  return [...new Set(coverage.controls.flatMap(x => x.sourceIds))]
    .sort().map(source => {
      const controls = coverage.controls.filter(x =>
        x.sourceIds.includes(source));
      const missing = controls.filter(x =>
        !x.verifiedForScoring);
      return {
        source, total: controls.length,
        observed: controls.filter(x =>
          x.verifiedForScoring).length,
        missing: missing.length,
        denied: controls.filter(x =>
          x.issues.includes("PERMISSION_DENIED")).length,
        incompleteControls: missing.map(x => x.controlId),
        canClaimTenantHealthy: false as const,
      };
    });
}
export function coverageV2Gaps(
  coverage: V2Coverage,
) {
  return coverage.controls.filter(x =>
    !x.verifiedForScoring).map(x => ({
    code: x.status, domain: x.domain,
    controlId: x.controlId, weight: x.weight,
    sourcesAttempted: [...x.sourceIds],
    sourcesAvailable: [...x.missingSources],
    evidenceIds: [...x.evidenceIds],
    uncertainty: [...x.uncertainty],
    shouldRecheck: ["STALE", "ERROR",
      "CONFLICT"].includes(x.status),
    priority: x.weight >= 10 ? "HIGH" as const :
      x.weight >= 7 ? "MEDIUM" as const : "NORMAL" as const,
    automaticallyResolved: false as const,
    customerComplianceProven: false as const,
  })).sort((a, b) => b.weight - a.weight ||
    a.controlId.localeCompare(b.controlId));
}
export function compareV2Coverage(
  previous: V2Coverage, current: V2Coverage,
) {
  if (previous.organizationId !== current.organizationId ||
      previous.modelId !== current.modelId)
    throw new Error("Cannot compare coverage across tenants or models.");
  if (previous.evaluatedAt > current.evaluatedAt)
    throw new Error("Coverage trend must be chronological.");
  const oldRows = new Map(previous.controls.map(x =>
    [x.controlId, x]));
  const rows = current.controls.map(now => {
    const before = oldRows.get(now.controlId);
    return {
      controlId: now.controlId, domain: now.domain,
      oldStatus: before?.status ?? "UNKNOWN",
      newStatus: now.status,
      oldVerified: before?.verifiedForScoring ?? false,
      newVerified: now.verifiedForScoring,
      oldEvidence: before?.evidenceIds ?? [],
      newEvidence: now.evidenceIds,
      scopeChanged: before?.scope !== now.scope,
      sourceChanged: JSON.stringify(before?.sourceIds ?? []) !==
        JSON.stringify(now.sourceIds),
      improvedVerifiedCoverage: !before?.verifiedForScoring &&
        now.verifiedForScoring,
      securityRemediationProven: false as const,
    };
  });
  const removed = previous.controls.filter(x =>
    !current.controls.some(n => n.controlId === x.controlId));
  return {
    organizationId: current.organizationId,
    modelId: current.modelId,
    baseline: previous.evaluatedAt,
    latest: current.evaluatedAt,
    oldCoveragePercent: previous.coveragePercent,
    newCoveragePercent: current.coveragePercent,
    deltaPercent: current.coveragePercent -
      previous.coveragePercent,
    changes: rows.filter(x => x.oldStatus !== x.newStatus ||
      x.scopeChanged || x.sourceChanged),
    removedControlIds: removed.map(x => x.controlId),
    sourceRevalidatedExternally: false as const,
    automaticallyRemediated: false as const,
    canonicalV1Changed: false as const,
  };
}
export function summarizeV2CoverageExecutive(
  coverage: V2Coverage,
) {
  const pending = coverageV2Gaps(coverage);
  return {
    organizationId: coverage.organizationId,
    at: coverage.evaluatedAt,
    controlsRequired: coverage.totalControls,
    controlsVerified: coverage.verifiedControls,
    controlCoveragePercent: coverage.coveragePercent,
    domains: coverage.domains.map(row => ({
      domain: row.domain, coveragePercent: row.coveragePercent,
      missing: row.missingControls.length,
      sourceCount: row.sources.length,
      readyForCertification: false as const,
    })),
    topUnknowns: pending.slice(0, 12),
    providerCount: coverage.sources.length,
    sourceAuthenticated: coverage.liveProviderAuthenticated,
    needsMoreEvidence: pending.length > 0,
    headline: coverage.coveragePercent === 0 ?
      "No sufficient evidence for a security posture score." :
      "Partial evidence collected; do not equate absence of findings to safety.",
    reliableHealthyClaim: false as const,
    customerCertification: false as const,
    oldCyberScorePreserved: true as const,
  };
}
