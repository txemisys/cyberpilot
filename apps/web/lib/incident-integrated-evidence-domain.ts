import { createHash } from "node:crypto";
import { getIncidentPlaybook, type IncidentType } from "./incident-playbook-catalog";
import { incidentDigest, validateIncidentSnapshot, type IncidentSnapshot } from "./incident-case-domain";

export type EvidenceSourceRow = {
  id: string; organizationId: string; source: string; domain: string;
  controlId: string; scope: string; state: string;
  observedAt: string | null; createdAt: string; updatedAt: string;
};
export type FindingSourceRow = {
  id: string; organizationId: string; key: string; ruleId: string;
  severity: string; status: string; title: string;
  lastSeenAt: string; resolvedAt: string | null;
};
export type DecisionSourceRow = {
  id: string; organizationId: string; domain: string; controlId: string;
  scope: string; status: string; revision: number;
  evidenceIds: string[]; findingIds: string[];
};
export type IncidentSourceSelection = {
  evidenceIds: string[]; findingIds: string[]; decisionIds: string[];
};
export type CorrelationBasis = "EXPLICIT_ID" | "DECISION_MEMBERSHIP" | "NO_MATCH";
export type CorrelationVerdict = "SUPPORTED_RECORD" | "DECLARED_RECORD" |
  "UNKNOWN_COVERAGE" | "STALE_RECORD" | "ERROR_RECORD" | "CONFLICT" |
  "MISSING_RECORD" | "CROSS_TENANT_REJECTED";
export type CorrelatedSource = {
  id: string; kind: "EVIDENCE" | "FINDING" | "DECISION";
  basis: CorrelationBasis; verdict: CorrelationVerdict;
  organizationId: string; incidentId: string; sourceId: string;
  sourceLabel: string; controlId: string | null; scope: string | null;
  observedAt: string | null; evidenceConfidence: "PERSISTED_OBSERVATION_NOT_PROVIDER_VERIFIED" |
    "DECLARED_OR_PARTIAL" | "UNDETERMINED";
  severity: string | null; status: string;
  linkedDecisionIds: string[]; requiredReview: boolean;
  signals: string[]; providerOutcomeVerified: false;
};
export type StepCorrelation = {
  stepId: string; title: string; capability: string;
  requiredSources: string[]; matchedEvidenceIds: string[];
  matchedFindingIds: string[]; matchedDecisionIds: string[];
  matchBasis: "EXPLICIT_ONLY" | "DECISION_DERIVED" | "NONE";
  missingSources: string[]; unknownSources: string[];
  staleSources: string[]; errorSources: string[];
  humanDeclarationCount: number; independentObservedCount: number;
  derivedFromIncidentEvidenceCount: number;
  completionGate: "BLOCKED" | "REQUIRES_MANUAL_REVIEW";
  verifiedProviderExecution: false;
};
export type IncidentEvidenceCorrelation = {
  schema: "cyberpilot.incident.evidence.correlation.v1";
  organizationId: string; incidentId: string; incidentType: IncidentType;
  generatedAt: string; incidentRevision: number;
  incidentDigest: string; sourceDigest: string;
  selectedEvidenceCount: number; selectedFindingCount: number;
  selectedDecisionCount: number; matchedEvidenceCount: number;
  matchedFindingCount: number; matchedDecisionCount: number;
  missingIds: string[]; duplicateIds: string[]; foreignTenantIds: string[];
  sourceRecords: CorrelatedSource[]; steps: StepCorrelation[];
  coverage: "EXPLICIT_PARTIAL" | "EXPLICIT_COMPLETE" | "NO_EXPLICIT_INPUT";
  acceptance: "BLOCKED" | "INCOMPLETE" | "READY_FOR_OPERATOR_REVIEW";
  warnings: string[]; truncated: boolean;
  recordLinkageEstablished: boolean; riskReductionProven: false;
  providerWrites: 0; actualIncidentContainmentConfirmed: false;
};
export type CorrelationInput = {
  incident: IncidentSnapshot; selection: IncidentSourceSelection;
  evidence: EvidenceSourceRow[]; findings: FindingSourceRow[];
  decisions: DecisionSourceRow[]; asOf: string; maxAgeHours: number;
  truncated: boolean;
};
const validId = (s: unknown): s is string => typeof s === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
const date = (s: unknown): s is string => typeof s === "string" &&
  Number.isFinite(Date.parse(s)) && new Date(s).toISOString() === s;
const digest = (value: unknown) => createHash("sha256")
  .update(JSON.stringify(value)).digest("hex");
const asIds = (input: unknown, limit: number): string[] => {
  if (!Array.isArray(input) || input.length > limit ||
      input.some(x => !validId(x)))
    throw Error("INCIDENT_CORRELATION_IDENTIFIERS_INVALID");
  return input as string[];
};
function validateInput(x: CorrelationInput) {
  if (validateIncidentSnapshot(x.incident).length ||
      !date(x.asOf) || !Number.isSafeInteger(x.maxAgeHours) ||
      x.maxAgeHours < 1 || x.maxAgeHours > 8760 ||
      x.evidence.length > 500 || x.findings.length > 500 ||
      x.decisions.length > 200)
    throw Error("INCIDENT_CORRELATION_INPUT_INVALID");
  asIds(x.selection.evidenceIds, 500);
  asIds(x.selection.findingIds, 500);
  asIds(x.selection.decisionIds, 200);
  if (typeof x.truncated !== "boolean") throw Error("INCIDENT_CORRELATION_TRUNCATION_INVALID");
}
function classifyEvidence(row: EvidenceSourceRow, asOf: string, ageHours: number) {
  const stamp = row.observedAt ? Date.parse(row.observedAt) : NaN;
  const unknown = row.state === "UNKNOWN";
  const error = row.state === "ERROR";
  const reported = row.state === "DECLARED";
  const stale = !Number.isFinite(stamp) ||
    stamp > Date.parse(asOf) || stamp < Date.parse(asOf) - ageHours * 3600000;
  const recognized = ["OBSERVED", "DECLARED", "UNKNOWN", "ERROR"].includes(row.state);
  const verdict: CorrelationVerdict = !recognized ? "UNKNOWN_COVERAGE" :
    error ? "ERROR_RECORD" : unknown ? "UNKNOWN_COVERAGE" :
    reported ? "DECLARED_RECORD" : stale ? "STALE_RECORD" : "SUPPORTED_RECORD";
  const signals = [
    ...(error ? ["PROVIDER_OR_COLLECTION_ERROR"] : []),
    ...(unknown ? ["COLLECTION_UNKNOWN"] : []),
    ...(reported ? ["DECLARED_NOT_INDEPENDENT"] : []),
    ...(stale ? ["MISSING_OR_STALE_OBSERVATION_TIME"] : []),
    ...(!["OBSERVED", "DECLARED", "UNKNOWN", "ERROR"].includes(row.state)
      ? ["UNRECOGNIZED_EVIDENCE_STATE"] : []),
  ];
  return { verdict: row.state === "OBSERVED" && !stale ?
      "SUPPORTED_RECORD" as const : verdict,
    signals, confidence: row.state === "OBSERVED" && !stale ?
      "PERSISTED_OBSERVATION_NOT_PROVIDER_VERIFIED" as const : reported ?
      "DECLARED_OR_PARTIAL" as const : "UNDETERMINED" as const };
}
function classifyFinding(row: FindingSourceRow, asOf: string, ageHours: number) {
  const seen = Date.parse(row.lastSeenAt);
  const stale = !Number.isFinite(seen) || seen > Date.parse(asOf) ||
    seen < Date.parse(asOf) - ageHours * 3600000;
  const closed = row.status !== "OPEN";
  return {
    verdict: stale ? "STALE_RECORD" as const :
      closed ? "DECLARED_RECORD" as const : "SUPPORTED_RECORD" as const,
    signals: [
      ...(stale ? ["FINDING_LAST_SEEN_OUT_OF_WINDOW"] : []),
      ...(closed ? ["FINDING_NOT_CURRENTLY_OPEN"] : []),
      ...(row.resolvedAt ? ["FINDING_REPORTED_RESOLVED_NOT_PROVIDER_VERIFIED"] : []),
    ], confidence: "DECLARED_OR_PARTIAL" as const,
  };
}
function selected(input: IncidentSourceSelection, kind: "evidenceIds" | "findingIds" | "decisionIds") {
  return new Set(input[kind]);
}
function collectDuplicates(input: IncidentSourceSelection) {
  return [...input.evidenceIds, ...input.findingIds, ...input.decisionIds]
    .filter((value, i, all) => all.indexOf(value) !== i);
}
function decisionMembership(x: DecisionSourceRow, id: string, kind: "EVIDENCE" | "FINDING") {
  return kind === "EVIDENCE" ? x.evidenceIds.includes(id) : x.findingIds.includes(id);
}
export function correlateIncidentEvidence(input: CorrelationInput): IncidentEvidenceCorrelation {
  validateInput(input);
  const { incident, selection, evidence, findings, decisions, asOf } = input;
  const selectedEvidence = selected(selection, "evidenceIds");
  const selectedFindings = selected(selection, "findingIds");
  const selectedDecisions = selected(selection, "decisionIds");
  const foreignTenantIds = [...evidence, ...findings, ...decisions]
    .filter(row => row.organizationId !== incident.organizationId).map(x => x.id);
  // Declared explicit references are the only join basis. A string match
  // between a phishing message, a hostname or a user is NEVER authoritative.
  const relevantDecisions = decisions.filter(x =>
    selectedDecisions.has(x.id) && x.organizationId === incident.organizationId);
  const derivedEvidenceIds = new Set(relevantDecisions.flatMap(x => x.evidenceIds));
  const derivedFindingIds = new Set(relevantDecisions.flatMap(x => x.findingIds));
  const sources: CorrelatedSource[] = [];
  for (const row of evidence) {
    if (row.organizationId !== incident.organizationId) continue;
    const basis: CorrelationBasis = selectedEvidence.has(row.id) ?
      "EXPLICIT_ID" : derivedEvidenceIds.has(row.id) ? "DECISION_MEMBERSHIP" : "NO_MATCH";
    if (basis === "NO_MATCH") continue;
    const result = classifyEvidence(row, asOf, input.maxAgeHours);
    const linkedDecisionIds = relevantDecisions.filter(d =>
      decisionMembership(d, row.id, "EVIDENCE")).map(d => d.id);
    sources.push({
      id: "EVIDENCE:" + row.id, kind: "EVIDENCE", basis,
      verdict: result.verdict, organizationId: row.organizationId,
      incidentId: incident.id, sourceId: row.id,
      sourceLabel: row.source + ":" + row.domain, controlId: row.controlId,
      scope: row.scope, observedAt: row.observedAt,
      evidenceConfidence: result.confidence, severity: null, status: row.state,
      linkedDecisionIds, requiredReview: result.verdict !== "SUPPORTED_RECORD",
      signals: result.signals, providerOutcomeVerified: false,
    });
  }
  for (const row of findings) {
    if (row.organizationId !== incident.organizationId) continue;
    const basis: CorrelationBasis = selectedFindings.has(row.id) ?
      "EXPLICIT_ID" : derivedFindingIds.has(row.id) ? "DECISION_MEMBERSHIP" : "NO_MATCH";
    if (basis === "NO_MATCH") continue;
    const result = classifyFinding(row, asOf, input.maxAgeHours);
    sources.push({
      id: "FINDING:" + row.id, kind: "FINDING", basis,
      verdict: result.verdict, organizationId: row.organizationId,
      incidentId: incident.id, sourceId: row.id,
      sourceLabel: row.ruleId, controlId: row.ruleId,
      scope: null, observedAt: row.lastSeenAt,
      evidenceConfidence: result.confidence, severity: row.severity,
      status: row.status, linkedDecisionIds: relevantDecisions.filter(d =>
        decisionMembership(d, row.id, "FINDING")).map(d => d.id),
      requiredReview: true, signals: result.signals,
      providerOutcomeVerified: false,
    });
  }
  for (const row of relevantDecisions) {
    sources.push({
      id: "DECISION:" + row.id, kind: "DECISION", basis: "EXPLICIT_ID",
      verdict: row.status === "OPEN" ? "DECLARED_RECORD" : "UNKNOWN_COVERAGE",
      organizationId: row.organizationId, incidentId: incident.id,
      sourceId: row.id, sourceLabel: row.domain, controlId: row.controlId,
      scope: row.scope, observedAt: null, evidenceConfidence: "DECLARED_OR_PARTIAL",
      severity: null, status: row.status, linkedDecisionIds: [row.id],
      requiredReview: true, signals: ["DECISION_WORKFLOW_NOT_PROVIDER_OUTCOME"],
      providerOutcomeVerified: false,
    });
  }
  const foundIds = new Set(sources.map(s => s.sourceId));
  const wanted = [...selectedEvidence, ...selectedFindings, ...selectedDecisions];
  const missingIds = wanted.filter(x => !foundIds.has(x));
  const duplicateIds = [...new Set(collectDuplicates(selection))];
  const book = getIncidentPlaybook(incident.type);
  const steps: StepCorrelation[] = book.steps.map(spec => {
    const attached = incident.evidence.filter(x => x.stepId === spec.id);
    const mapped = sources.filter(s => s.kind === "EVIDENCE" &&
      spec.requiredEvidence.some(req =>
        s.sourceLabel === req || s.sourceLabel.startsWith(req + ":")));
    // Persistence of OBSERVED is not, by itself, independent provider proof.
    // The SecurityEvidence table does not encode a cryptographic verifier chain.
    const independent: CorrelatedSource[] = [];
    const required = spec.requiredEvidence.filter(x => x !== "approval");
    const present = required.filter(source => independent.some(x =>
      x.sourceLabel === source || x.sourceLabel.startsWith(source + ":")));
    const missingSources = required.filter(x => !present.includes(x));
    const unknownSources = mapped.filter(x => x.verdict === "UNKNOWN_COVERAGE")
      .map(x => x.sourceLabel);
    const staleSources = mapped.filter(x => x.verdict === "STALE_RECORD")
      .map(x => x.sourceLabel);
    const errorSources = mapped.filter(x => x.verdict === "ERROR_RECORD")
      .map(x => x.sourceLabel);
    const linkedDecisionIds = [...new Set(mapped.flatMap(x => x.linkedDecisionIds))];
    const matchedFindings = sources.filter(x => x.kind === "FINDING" &&
      x.linkedDecisionIds.some(id => linkedDecisionIds.includes(id)));
    return {
      stepId: spec.id, title: spec.title, capability: spec.providerCapability,
      requiredSources: required,
      matchedEvidenceIds: mapped.map(x => x.sourceId),
      matchedFindingIds: matchedFindings.map(x => x.sourceId),
      matchedDecisionIds: linkedDecisionIds,
      matchBasis: mapped.some(x => x.basis === "EXPLICIT_ID") ?
        "EXPLICIT_ONLY" as const : mapped.length ? "DECISION_DERIVED" as const :
        "NONE" as const,
      missingSources, unknownSources, staleSources, errorSources,
      humanDeclarationCount: attached.filter(x => !x.independent ||
        x.verdict === "DECLARED").length,
      independentObservedCount: independent.length,
      derivedFromIncidentEvidenceCount: attached.length,
      completionGate: missingSources.length || spec.requiresApproval ?
        "BLOCKED" as const : "REQUIRES_MANUAL_REVIEW" as const,
      verifiedProviderExecution: false as const,
    };
  });
  const warnings = [
    ...(input.truncated ? ["SOURCE_PAGE_TRUNCATED"] : []),
    ...(foreignTenantIds.length ? ["CROSS_TENANT_SOURCE_REJECTED"] : []),
    ...(missingIds.length ? ["REFERENCED_SOURCE_MISSING"] : []),
    ...(duplicateIds.length ? ["DUPLICATE_SELECTION_IDS"] : []),
    ...(steps.some(s => s.missingSources.length) ? ["PLAYBOOK_SOURCES_INCOMPLETE"] : []),
    ...(sources.some(x => x.verdict === "ERROR_RECORD") ? ["SOURCE_COLLECTION_ERROR"] : []),
    ...(sources.some(x => x.verdict === "STALE_RECORD") ? ["SOURCE_STALE"] : []),
    ...(incident.status === "CLOSED" ? ["WORKFLOW_CLOSED_NOT_CONTAINMENT_PROOF"] : []),
  ];
  const acceptance = foreignTenantIds.length || duplicateIds.length ?
    "BLOCKED" as const : warnings.length ? "INCOMPLETE" as const :
    "READY_FOR_OPERATOR_REVIEW" as const;
  return {
    schema: "cyberpilot.incident.evidence.correlation.v1",
    organizationId: incident.organizationId, incidentId: incident.id,
    incidentType: incident.type, generatedAt: asOf,
    incidentRevision: incident.revision, incidentDigest: incidentDigest(incident),
    sourceDigest: digest({
      evidence: evidence.map(x => [x.id, x.state, x.observedAt]),
      findings: findings.map(x => [x.id, x.status, x.lastSeenAt]),
      decisions: decisions.map(x => [x.id, x.revision]),
    }),
    selectedEvidenceCount: selection.evidenceIds.length,
    selectedFindingCount: selection.findingIds.length,
    selectedDecisionCount: selection.decisionIds.length,
    matchedEvidenceCount: sources.filter(x => x.kind === "EVIDENCE").length,
    matchedFindingCount: sources.filter(x => x.kind === "FINDING").length,
    matchedDecisionCount: relevantDecisions.length,
    missingIds, duplicateIds, foreignTenantIds,
    sourceRecords: sources.sort((a, b) => a.id.localeCompare(b.id)),
    steps, coverage: wanted.length === 0 ? "NO_EXPLICIT_INPUT" :
      missingIds.length ? "EXPLICIT_PARTIAL" : "EXPLICIT_COMPLETE",
    acceptance, warnings, truncated: input.truncated,
    recordLinkageEstablished: sources.length > 0, riskReductionProven: false,
    providerWrites: 0, actualIncidentContainmentConfirmed: false,
  };
}
export function compareIncidentCorrelations(
  earlier: IncidentEvidenceCorrelation, later: IncidentEvidenceCorrelation) {
  if (earlier.organizationId !== later.organizationId ||
      earlier.incidentId !== later.incidentId ||
      earlier.generatedAt > later.generatedAt)
    throw Error("INCIDENT_CORRELATION_COMPARISON_SCOPE_INVALID");
  const previous = new Map(earlier.sourceRecords.map(x => [x.id, x]));
  const current = new Map(later.sourceRecords.map(x => [x.id, x]));
  return {
    schema: "cyberpilot.incident.evidence.correlation-diff.v1" as const,
    organizationId: earlier.organizationId, incidentId: earlier.incidentId,
    added: [...current.keys()].filter(x => !previous.has(x)),
    removed: [...previous.keys()].filter(x => !current.has(x)),
    changedVerdicts: [...current.values()].filter(x =>
      previous.has(x.id) && previous.get(x.id)!.verdict !== x.verdict).map(x =>
      ({ id: x.id, before: previous.get(x.id)!.verdict, after: x.verdict })),
    remainingMissing: later.missingIds,
    partialHistory: earlier.truncated || later.truncated,
    operationalRiskReduced: false as const,
    externalProviderVerified: false as const,
  };
}
