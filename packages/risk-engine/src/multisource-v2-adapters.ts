import {
  type SecurityEvidenceV1, type EvidenceSource,
} from "./evidence";
import {
  type V2Manifest, type V2Evidence,
  type V2ControlSpec, type V2Scope,
  type V2Finding, type V2Source,
  type V2State, type V2Domain,
  type V2ScopeKind, type V2Confidence,
  type V2Verification, type V2Severity,
  emptyV2Manifest, defaultV2Controls,
  validateV2Manifest, validV2Id, validV2Time,
  canonicalV2, validV2String,
} from "./multisource-v2-contract";
import { sha256V2 } from "./multisource-v2-history";

/**
 * Source adapters are conservative by default. A source may become
 * technically eligible only when an independently verified complete
 * scope is provided. Fixture provenance cannot be promoted to LIVE.
 */
export type V2AdapterContext = {
  organizationId: string;
  evaluatedAt: string;
  snapshotId: string;
  authority: string;
  sourceReference: string;
  sourceDigest: string;
  scope: string;
  scopeKind: V2ScopeKind;
  observedSubjects: number | null;
  expectedSubjects: number | null;
  pagesRead: number | null;
  expectedPages: number | null;
  status: V2Scope["status"];
  providerAuthenticated: boolean;
  scopeAuthenticityVerified: boolean;
  sourceIsSynthetic: boolean;
  allowTechnicalProof: boolean;
  maxAgeDays: number;
};
export type V2AdapterRawFinding = {
  id: string;
  ruleId: string;
  controlId: string;
  domain: V2Domain;
  severity: V2Severity;
  state: "POTENTIAL_RISK" | "REQUIRES_REVIEW" |
    "UNKNOWN";
  title: string;
  explanation: string;
  remediation: string;
  sourceId: string;
  subjectId: string;
  observedAt: string;
  confidence: V2Confidence;
};
export type V2AdapterObservation = {
  schema: "cyberpilot.multisource.adapter.observation.v2";
  externalId: string;
  subjectId: string;
  controlId: string;
  domain: V2Domain;
  state: V2State;
  confidence: V2Confidence;
  observedAt: string | null;
  checkedAt: string;
  scope: string;
  details: Record<string, string | number | boolean | null>;
  provenance: string;
};
export type V2AdapterBatch = {
  schema: "cyberpilot.multisource.adapter.batch.v2";
  organizationId: string;
  source: V2Source;
  sourceDigest: string;
  sourceReference: string;
  observedAt: string;
  checkedAt: string;
  observations: V2AdapterObservation[];
  findings: V2AdapterRawFinding[];
  scopes: V2Scope[];
  capabilitiesObserved: number;
  capabilitiesUnknown: number;
  technicalEvidence: boolean;
  providerAuthenticated: boolean;
  simulated: boolean;
  containsPII: false;
  accountWrites: 0;
  externalApprovalAttested: false;
  warnings: string[];
};
export type V2MultiSourceIntake = {
  schema: "cyberpilot.multisource.intake.v2";
  organizationId: string;
  modelId: "cyberpilot.multisource.v2";
  evaluatedAt: string;
  snapshotId: string;
  batches: V2AdapterBatch[];
  requiredControls: V2ControlSpec[];
  allowUnverifiedSources: true;
  allowForeignTenants: false;
  legacyScoreMigration: false;
  externalCustomerConsentClaimed: false;
};
export type V2AdapterResult = {
  manifest: V2Manifest;
  acceptedSources: V2Source[];
  importedEvidence: number;
  importedFindings: number;
  importedScopes: number;
  rejectedSources: string[];
  duplicatedSourceDigests: string[];
  warnings: string[];
  sourceTenantsEnforced: true;
  scoreCalculated: false;
  historyModified: false;
};
const known: readonly V2Source[] = [
  "MICROSOFT_365", "GOOGLE_WORKSPACE",
  "LAB", "EXPOSURE", "BASELINE", "ASSETS",
];
function id(v: unknown, label: string) {
  if (!validV2Id(v))
    throw new Error("Invalid v2 adapter " + label + ".");
  return v as string;
}
function validDigest(v: string) {
  return /^[0-9a-f]{64}$/.test(v);
}
function checkedTime(at: string) {
  if (!validV2Time(at))
    throw new Error("Invalid adapter observation timestamp.");
  return at;
}
function checkedContext(context: V2AdapterContext) {
  id(context.organizationId, "organizationId");
  id(context.snapshotId, "snapshotId");
  checkedTime(context.evaluatedAt);
  if (!validDigest(context.sourceDigest) ||
      !validV2String(context.authority, 256) ||
      !validV2String(context.sourceReference, 512) ||
      !validV2String(context.scope, 512))
    throw new Error("Invalid adapter source provenance.");
  if (!Number.isInteger(context.maxAgeDays) ||
      context.maxAgeDays < 1 || context.maxAgeDays > 3650)
    throw new Error("Invalid adapter freshness policy.");
  if (context.allowTechnicalProof &&
      context.sourceIsSynthetic)
    throw new Error("A synthetic fixture cannot establish independent technical proof.");
}
function source(source: V2Source): V2Source {
  if (!known.includes(source))
    throw new Error("Unknown source for v2 intake.");
  return source;
}
function mapping(source: EvidenceSource): V2Source {
  if (source === "DOMAIN") return "EXPOSURE";
  if (known.includes(source as V2Source))
    return source as V2Source;
  throw new Error("Unsupported legacy evidence source.");
}
function hashIdentity(
  org: string, source: V2Source, identity: string,
) {
  return sha256V2(org + "\u0000" + source +
    "\u0000" + identity);
}
function sourceProof(context: V2AdapterContext) {
  return context.allowTechnicalProof &&
    !context.sourceIsSynthetic &&
    context.scopeAuthenticityVerified &&
    context.status === "COMPLETE" &&
    context.expectedSubjects !== null &&
    context.observedSubjects !== null &&
    context.observedSubjects >= context.expectedSubjects &&
    (context.expectedPages === null ||
      context.pagesRead === context.expectedPages);
}
export function buildV2AdapterScope(
  source: V2Source, domain: V2Domain,
  context: V2AdapterContext,
): V2Scope {
  checkedContext(context);
  const proof = sourceProof(context);
  return {
    organizationId: context.organizationId,
    source, domain,
    scopeKind: context.scopeKind,
    scope: context.scope,
    expectedSubjects: context.expectedSubjects,
    observedSubjects: context.observedSubjects,
    totalPages: context.expectedPages,
    pagesObserved: context.pagesRead,
    status: context.status,
    checkedAt: context.evaluatedAt,
    validUntil: new Date(Date.parse(context.evaluatedAt) +
      context.maxAgeDays * 86400000).toISOString(),
    sourceDigest: context.sourceDigest,
    customerTenantAuthenticated: context.providerAuthenticated &&
      proof,
    scopeAuthenticityVerified: proof,
    errors: proof ? [] : [
      "Source completeness or independent authenticity is unverified.",
    ],
  };
}
export function convertLegacyV1Evidence(
  input: readonly SecurityEvidenceV1[],
  context: V2AdapterContext,
): V2AdapterBatch[] {
  checkedContext(context);
  if (input.length > 50000)
    throw new Error("Legacy v1 adapter input too large.");
  const groups = new Map<V2Source, SecurityEvidenceV1[]>();
  for (const item of input) {
    if (item.organizationId !== context.organizationId)
      throw new Error("Legacy evidence from another organization.");
    const mapped = mapping(item.source);
    groups.set(mapped, [...groups.get(mapped) ?? [], item]);
  }
  return [...groups.entries()].map(([provider, items]) => {
    const domains = [...new Set(items.map(x =>
      x.domain as V2Domain))];
    const observations = items.map((item, index) => {
      if (!validV2Id(item.controlId))
        throw new Error("Invalid legacy control ID.");
      const observedAt = item.observedAt instanceof Date &&
        Number.isFinite(item.observedAt.getTime()) ?
          item.observedAt.toISOString() : null;
      const state = item.state;
      return {
        schema: "cyberpilot.multisource.adapter.observation.v2" as const,
        externalId: "legacy-v1-" + index + "-" + item.controlId,
        subjectId: "v1-control-" + item.controlId + "-" + index,
        controlId: item.controlId, domain: item.domain as V2Domain,
        state, confidence: state === "OBSERVED" ?
          "LOW" as const : "UNKNOWN" as const,
        observedAt, checkedAt: context.evaluatedAt,
        scope: item.scope,
        details: { ...item.details },
        provenance: "legacy-v1-translated-not-promoted",
      };
    });
    const scopes = domains.map(domain =>
      buildV2AdapterScope(provider, domain, {
        ...context, sourceIsSynthetic: true,
        allowTechnicalProof: false,
        providerAuthenticated: false,
        scopeAuthenticityVerified: false,
        status: "UNASSESSED",
      }));
    return {
      schema: "cyberpilot.multisource.adapter.batch.v2" as const,
      organizationId: context.organizationId,
      source: provider,
      sourceDigest: context.sourceDigest,
      sourceReference: context.sourceReference,
      observedAt: context.evaluatedAt,
      checkedAt: context.evaluatedAt,
      observations, findings: [], scopes,
      capabilitiesObserved: observations.filter(x =>
        x.state === "OBSERVED").length,
      capabilitiesUnknown: observations.filter(x =>
        x.state !== "OBSERVED").length,
      technicalEvidence: false,
      providerAuthenticated: false, simulated: true,
      containsPII: false as const, accountWrites: 0 as const,
      externalApprovalAttested: false as const,
      warnings: [
        "v1 translation is a read-only compatibility projection.",
        "Original v1 source authenticity cannot be inferred from legacy rows.",
        "No new CyberScore v2 coverage is granted by an unverified legacy import.",
      ],
    };
  });
}
export function createV2AdapterBatch(
  sourceId: V2Source, context: V2AdapterContext,
  observations: readonly V2AdapterObservation[],
  findings: readonly V2AdapterRawFinding[] = [],
): V2AdapterBatch {
  checkedContext(context);
  source(sourceId);
  if (observations.length > 10000 ||
      findings.length > 10000)
    throw new Error("Adapter record count exceeds safe bound.");
  const proof = sourceProof(context);
  const validated = observations.map(observation => {
    if (observation.schema !==
        "cyberpilot.multisource.adapter.observation.v2" ||
        !validV2Id(observation.externalId) ||
        !validV2String(observation.subjectId, 512) ||
        !validV2Id(observation.controlId) ||
        !validV2Time(observation.checkedAt) ||
        observation.checkedAt > context.evaluatedAt ||
        observation.observedAt !== null &&
          !validV2Time(observation.observedAt) ||
        observation.observedAt !== null &&
          observation.observedAt > context.evaluatedAt ||
        observation.scope !== context.scope)
      throw new Error("Invalid or out-of-scope adapter observation.");
    if (observation.state === "OBSERVED" &&
        observation.observedAt === null)
      throw new Error("A technical observation needs observedAt.");
    if (Object.keys(observation.details).some(k =>
      /(email|phone|password|token|secret|credential|ipaddress)/i.test(k)))
      throw new Error("Unredacted adapter details are not supported.");
    return { ...observation, details: { ...observation.details } };
  });
  const scopes = [...new Set(validated.map(x => x.domain))]
    .map(domain => buildV2AdapterScope(sourceId, domain, context));
  const acceptedFindings = findings.map(item => {
    if (!validV2Id(item.id) ||
        !validV2Id(item.ruleId) ||
        !validV2Id(item.controlId) ||
        !validV2Time(item.observedAt) ||
        item.observedAt > context.evaluatedAt ||
        !validV2String(item.title) ||
        !validV2String(item.explanation, 1000) ||
        !validV2String(item.remediation, 1000) ||
        !validated.some(o => o.externalId === item.sourceId &&
          o.controlId === item.controlId &&
          o.domain === item.domain))
      throw new Error("Finding has invalid or missing source observation.");
    return { ...item };
  });
  return {
    schema: "cyberpilot.multisource.adapter.batch.v2",
    organizationId: context.organizationId,
    source: sourceId,
    sourceDigest: context.sourceDigest,
    sourceReference: context.sourceReference,
    observedAt: context.evaluatedAt,
    checkedAt: context.evaluatedAt,
    observations: validated, findings: acceptedFindings,
    scopes,
    capabilitiesObserved: validated.filter(x =>
      x.state === "OBSERVED").length,
    capabilitiesUnknown: validated.filter(x =>
      x.state !== "OBSERVED").length,
    technicalEvidence: proof,
    providerAuthenticated: context.providerAuthenticated && proof,
    simulated: context.sourceIsSynthetic,
    containsPII: false, accountWrites: 0,
    externalApprovalAttested: false,
    warnings: proof ? [
      "Source completeness is verified only for the supplied scope, not the whole enterprise.",
    ] : [
      "Source is not independently verified for trusted scoring.",
      "Declared or partial controls remain explicitly uncertain.",
    ],
  };
}
export function buildV2Intake(
  context: V2AdapterContext,
  batches: readonly V2AdapterBatch[],
  requiredControls: V2ControlSpec[] = defaultV2Controls(),
): V2MultiSourceIntake {
  checkedContext(context);
  if (batches.length > 100 ||
      requiredControls.length > 5000)
    throw new Error("Source intake exceeds capacity.");
  if (batches.some(b =>
    b.organizationId !== context.organizationId ||
    !known.includes(b.source) ||
    b.accountWrites !== 0 ||
    b.containsPII ||
    b.externalApprovalAttested))
    throw new Error("Unsupported tenant, PII or mutation in v2 intake.");
  return {
    schema: "cyberpilot.multisource.intake.v2",
    organizationId: context.organizationId,
    modelId: "cyberpilot.multisource.v2",
    evaluatedAt: context.evaluatedAt,
    snapshotId: context.snapshotId,
    batches: [...batches],
    requiredControls: [...requiredControls],
    allowUnverifiedSources: true,
    allowForeignTenants: false,
    legacyScoreMigration: false,
    externalCustomerConsentClaimed: false,
  };
}
function toEvidence(
  source: V2AdapterBatch,
  observation: V2AdapterObservation,
  control: V2ControlSpec,
): V2Evidence {
  const trusted = source.technicalEvidence &&
    !source.simulated &&
    observation.state === "OBSERVED";
  const declared = observation.state === "DECLARED";
  const verification: V2Verification =
    trusted ? "TECHNICALLY_VERIFIED" :
      source.simulated ? "SYNTHETIC_FIXTURE" :
      declared ? "OPERATOR_DECLARED" : "NOT_VERIFIED";
  const evidenceId = "v2-" + sha256V2(
    source.organizationId + "|" + source.source +
    "|" + observation.externalId).slice(0, 36);
  return {
    schema: "cyberpilot.multisource.evidence.v2",
    organizationId: source.organizationId,
    evidenceId, source: source.source,
    domain: observation.domain,
    controlId: observation.controlId,
    scope: observation.scope,
    scopeKind: control.scope,
    subjectHash: hashIdentity(source.organizationId,
      source.source, observation.subjectId),
    state: observation.state,
    confidence: trusted ? observation.confidence :
      observation.state === "OBSERVED" ?
        "LOW" : "UNKNOWN",
    verification,
    observedAt: observation.observedAt,
    checkedAt: observation.checkedAt,
    validUntil: null,
    sourceDigest: source.sourceDigest,
    sourceReference: source.sourceReference,
    authority: observation.provenance,
    sourceCoverage: source.scopes.some(s =>
      s.domain === observation.domain &&
      s.status === "COMPLETE" &&
      s.scopeAuthenticityVerified) ?
        "COMPLETE" : source.scopes.some(s =>
          s.domain === observation.domain &&
          s.status === "PERMISSION_DENIED") ?
            "DENIED" : "PARTIAL",
    details: { ...observation.details },
    rawPersonalDataStored: false,
    providerAccountModified: false,
    customerApprovalInferred: false,
  };
}
function toFinding(
  batch: V2AdapterBatch,
  item: V2AdapterRawFinding,
  observations: V2Evidence[],
): V2Finding {
  const original = batch.observations.find(o =>
    o.externalId === item.sourceId);
  if (!original)
    throw new Error("Adapter finding reference is unknown.");
  const linked = observations.find(e =>
    e.controlId === item.controlId &&
    e.subjectHash === hashIdentity(
      batch.organizationId, batch.source,
      original.subjectId));
  if (!linked)
    throw new Error("Adapter finding source evidence unavailable.");
  return {
    schema: "cyberpilot.multisource.finding.v2",
    organizationId: batch.organizationId,
    findingId: "v2finding-" + sha256V2(
      batch.organizationId + "|" + batch.source +
      "|" + item.id).slice(0, 32),
    ruleId: item.ruleId, domain: item.domain,
    controlId: item.controlId, scope: linked.scope,
    subjectHash: linked.subjectHash,
    source: batch.source,
    severity: item.severity, state: item.state,
    title: item.title, explanation: item.explanation,
    remediation: item.remediation,
    evidenceIds: [linked.evidenceId],
    observedAt: item.observedAt,
    confidence: item.confidence,
    autoRemediated: false, customerAccepted: false,
    resolved: false,
  };
}
export function assembleV2Intake(
  input: V2MultiSourceIntake,
): V2AdapterResult {
  if (input.schema !== "cyberpilot.multisource.intake.v2" ||
      input.modelId !== "cyberpilot.multisource.v2" ||
      input.allowForeignTenants ||
      input.legacyScoreMigration ||
      input.externalCustomerConsentClaimed ||
      !input.allowUnverifiedSources)
    throw new Error("Invalid or privileged source intake.");
  const manifest = emptyV2Manifest(
    input.organizationId, input.evaluatedAt,
    input.snapshotId, input.requiredControls);
  const allowed = new Map(input.requiredControls.map(c =>
    [c.id, c]));
  const rejectedSources: string[] = [];
  const duplicateDigests: string[] = [];
  const seenBatches = new Set<string>();
  const warnings: string[] = [];
  for (const batch of input.batches) {
    if (batch.organizationId !== input.organizationId ||
        batch.accountWrites !== 0 ||
        batch.containsPII ||
        batch.externalApprovalAttested)
      throw new Error("Unsafe multi-source batch.");
    const batchKey = [
      batch.source, batch.sourceDigest,
      batch.sourceReference,
    ].join("|");
    if (seenBatches.has(batchKey)) {
      duplicateDigests.push(batch.sourceDigest);
      continue;
    }
    seenBatches.add(batchKey);
    const observations: V2Evidence[] = [];
    for (const observation of batch.observations) {
      const control = allowed.get(observation.controlId);
      if (!control ||
          control.domain !== observation.domain ||
          !control.acceptedSources.includes(batch.source)) {
        rejectedSources.push(batch.source + ":" +
          observation.externalId);
        continue;
      }
      observations.push(toEvidence(batch, observation, control));
    }
    manifest.evidence.push(...observations);
    for (const finding of batch.findings) {
      if (!allowed.has(finding.controlId)) {
        rejectedSources.push(batch.source + ":" + finding.id);
        continue;
      }
      manifest.findings.push(toFinding(batch, finding, observations));
    }
    manifest.scopes.push(...batch.scopes);
    manifest.sourceDigests.push(batch.sourceDigest);
    warnings.push(...batch.warnings);
  }
  manifest.sourceDigests = [...new Set(manifest.sourceDigests)];
  const validation = validateV2Manifest(manifest);
  if (!validation.valid)
    throw new Error("Multi-source intake failed v2 contract: " +
      [...validation.errors, ...validation.conflicts,
        ...validation.crossTenant].slice(0, 8).join(","));
  return {
    manifest, acceptedSources: [...new Set(
      manifest.evidence.map(e => e.source))],
    importedEvidence: manifest.evidence.length,
    importedFindings: manifest.findings.length,
    importedScopes: manifest.scopes.length,
    rejectedSources, duplicatedSourceDigests: duplicateDigests,
    warnings: [...new Set(warnings)],
    sourceTenantsEnforced: true,
    scoreCalculated: false,
    historyModified: false,
  };
}
export function reviewV2IntakeSourceReadiness(
  result: V2AdapterResult,
) {
  const stats = result.acceptedSources.map(source => {
    const sourceEvidence = result.manifest.evidence.filter(e =>
      e.source === source);
    const sourceScopes = result.manifest.scopes.filter(s =>
      s.source === source);
    return {
      source, evidence: sourceEvidence.length,
      domains: [...new Set(sourceEvidence.map(e =>
        e.domain))],
      scopes: sourceScopes.length,
      verifiedEvidence: sourceEvidence.filter(e =>
        e.verification === "TECHNICALLY_VERIFIED").length,
      declaredEvidence: sourceEvidence.filter(e =>
        e.state === "DECLARED").length,
      unknownEvidence: sourceEvidence.filter(e =>
        e.state === "UNKNOWN" || e.state === "ERROR").length,
      authenticatedScopes: sourceScopes.filter(s =>
        s.customerTenantAuthenticated).length,
      missingFullCoverage: sourceScopes.filter(s =>
        s.status !== "COMPLETE").length,
      fullCustomerSecurityClaimed: false as const,
    };
  });
  return {
    organizationId: result.manifest.organizationId,
    sourceSummaries: stats,
    totalSources: result.acceptedSources.length,
    importedEvidence: result.importedEvidence,
    rejected: result.rejectedSources.length,
    canClaimRegulatoryCompliance: false as const,
    automaticallyMigratedLegacyScore: false as const,
  };
}
export function importV2SourceAuditManifest(
  input: V2MultiSourceIntake,
) {
  const result = assembleV2Intake(input);
  return {
    schema: "cyberpilot.multisource.intake.audit.v2" as const,
    organizationId: input.organizationId,
    snapshotId: input.snapshotId,
    sourceDigests: [...result.manifest.sourceDigests],
    imports: result.acceptedSources,
    batchCount: input.batches.length,
    evidenceCount: result.importedEvidence,
    findingsCount: result.importedFindings,
    scopeCount: result.importedScopes,
    duplicateDigests: [...result.duplicatedSourceDigests],
    rejectedRows: [...result.rejectedSources],
    sourceFingerprint: sha256V2(canonicalV2(
      result.manifest)),
    auditedAt: input.evaluatedAt,
    customerIdentityVerified: false as const,
    providerCryptographicSignature: false as const,
    historicalCyberScoreV1Touched: false as const,
    securityActionsPerformed: 0 as const,
  };
}
