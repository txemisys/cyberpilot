import { createHash } from "node:crypto";

export const SIEM_FORMATS = ["JSONL", "ECS", "CEF", "CSV"] as const;
export type SiemFormat = typeof SIEM_FORMATS[number];
export type AuditActor = "USER" | "SYSTEM" | "INTEGRATION" | "UNKNOWN";
export type AuditConfidence = "PERSISTED" | "PARTIAL" | "MALFORMED";
export type AuditSeverity = "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AuditActivity = "AUTHENTICATION" | "AUTHORIZATION" |
  "CONSENT" | "REMEDIATION" | "EVIDENCE" | "INCIDENT" | "INTEGRATION" |
  "CONFIGURATION" | "GENERAL";
export type PortableAuditInput = {
  id: string; organizationId: string; actorType: string;
  actorUserId: string | null; action: string; resourceType: string;
  resourceId: string | null; metadata: unknown; occurredAt: string;
};
export type PortableAuditEvent = {
  schema: "cyberpilot.siem.event.v1"; eventId: string; organizationId: string;
  occurredAt: string; actorType: AuditActor; actorReference: string | null;
  action: string; category: AuditActivity; severity: AuditSeverity;
  resourceType: string; resourceReference: string | null;
  confidence: AuditConfidence; metadataFields: Record<string, string | number | boolean>;
  redactedFields: number; malformedMetadata: boolean;
  source: "CYBERPILOT_PERSISTED_AUDIT"; actualRemediationProven: false;
  transmissionVerified: false;
};
export type SiemExportPolicy = {
  includeActorReferences: boolean; includeResourceReferences: boolean;
  allowlistedMetadataKeys: string[]; maxMetadataValueLength: number;
  maximumEvents: number; resourceReferenceMode: "NONE" | "HASH" | "EXPLICIT";
};
export const DEFAULT_SIEM_POLICY: Readonly<SiemExportPolicy> = Object.freeze({
  includeActorReferences: false, includeResourceReferences: false,
  allowlistedMetadataKeys: ["result", "status", "decision", "reasonCode",
    "failureCode", "mode", "coverage", "revision", "count",
    "durationMs", "provider", "type", "phase", "trigger"],
  maxMetadataValueLength: 128, maximumEvents: 100,
  resourceReferenceMode: "HASH",
});
const identifiers = (v: unknown): v is string => typeof v === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(v);
const validDate = (v: unknown): v is string => typeof v === "string" &&
  Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const plainField = (v: unknown): v is string | number | boolean =>
  typeof v === "boolean" || typeof v === "number" && Number.isFinite(v) ||
  typeof v === "string" && v.length <= 512 && !/[\u0000-\u001f\u007f]/.test(v);
function sha(value: string) { return createHash("sha256").update(value).digest("hex"); }
const forbidden = /(token|secret|passw|credential|authorization|cookie|session|bearer|private|api.?key|email|phone|account|bank|iban|payload|url|body|message|headers|ipaddress|full.?name)/i;
export function validateSiemPolicy(policy: SiemExportPolicy): string[] {
  const issues: string[] = [];
  if (!Number.isSafeInteger(policy.maxMetadataValueLength) ||
    policy.maxMetadataValueLength < 16 || policy.maxMetadataValueLength > 256)
    issues.push("SIEM_POLICY_VALUE_LIMIT");
  if (!Number.isSafeInteger(policy.maximumEvents) ||
    policy.maximumEvents < 1 || policy.maximumEvents > 500)
    issues.push("SIEM_POLICY_EVENT_LIMIT");
  if (!["NONE", "HASH", "EXPLICIT"].includes(policy.resourceReferenceMode))
    issues.push("SIEM_POLICY_REFERENCE_MODE");
  if (!Array.isArray(policy.allowlistedMetadataKeys) ||
      policy.allowlistedMetadataKeys.length > 30 ||
      policy.allowlistedMetadataKeys.some(key =>
        typeof key !== "string" || !/^[a-z][A-Za-z0-9]{1,39}$/.test(key) ||
        forbidden.test(key)) ||
      new Set(policy.allowlistedMetadataKeys).size !==
      policy.allowlistedMetadataKeys.length)
    issues.push("SIEM_POLICY_METADATA_KEY_UNSAFE");
  if (typeof policy.includeActorReferences !== "boolean" ||
      typeof policy.includeResourceReferences !== "boolean")
    issues.push("SIEM_POLICY_PII_FLAG_INVALID");
  return issues;
}
export function classifyAuditAction(action: string) : {
  category: AuditActivity; severity: AuditSeverity;
} {
  const label = action.toLowerCase();
  if (/auth|login|sign.?in|mfa|session/.test(label))
    return { category: "AUTHENTICATION", severity:
      /failed|denied|blocked|revok/.test(label) ? "HIGH" : "INFORMATIONAL" };
  if (/permission|rbac|access|role|privilege|membership/.test(label))
    return { category: "AUTHORIZATION", severity:
      /grant|elevat|denied|revok|reassign/.test(label) ? "HIGH" : "MEDIUM" };
  if (/consent|oauth/.test(label))
    return { category: "CONSENT", severity: "HIGH" };
  if (/remediat|execut|delete|purge|wipe|isolat|reset/.test(label))
    return { category: "REMEDIATION", severity: "CRITICAL" };
  if (/incident|compromis|phish|ransom|fraud/.test(label))
    return { category: "INCIDENT", severity: "HIGH" };
  if (/finding|evidence|score|assess|review/.test(label))
    return { category: "EVIDENCE", severity: "MEDIUM" };
  if (/integration|sync|provider|graph/.test(label))
    return { category: "INTEGRATION", severity:
      /fail|error/.test(label) ? "HIGH" : "LOW" };
  if (/config|setting|policy|secret|rotation/.test(label))
    return { category: "CONFIGURATION", severity: "MEDIUM" };
  return { category: "GENERAL", severity: "LOW" };
}
export function redactAuditMetadata(metadata: unknown,
  policy: SiemExportPolicy = DEFAULT_SIEM_POLICY) {
  if (validateSiemPolicy(policy).length) throw Error("SIEM_POLICY_INVALID");
  if (metadata === null || metadata === undefined)
    return { values: {} as Record<string, string | number | boolean>,
      removed: 0, malformed: false };
  if (typeof metadata !== "object" || Array.isArray(metadata))
    return { values: {} as Record<string, string | number | boolean>,
      removed: 1, malformed: true };
  const input = metadata as Record<string, unknown>;
  const values: Record<string, string | number | boolean> = {};
  let removed = 0, malformed = false;
  for (const [key, value] of Object.entries(input)) {
    if (!policy.allowlistedMetadataKeys.includes(key) || forbidden.test(key) ||
        !plainField(value) ||
        typeof value === "string" &&
          (value.length > policy.maxMetadataValueLength ||
          /[@\/?#=&]|https?:|[\r\n]|^eyJ|^[A-Za-z0-9+/_-]{40,}=?$/.test(value))) {
      removed++;
      if (!plainField(value)) malformed = true;
      continue;
    }
    values[key] = value;
  }
  return { values, removed, malformed };
}
function actor(raw: string): AuditActor {
  return raw === "USER" || raw === "SYSTEM" || raw === "INTEGRATION" ? raw : "UNKNOWN";
}
export function normalizePortableAuditEvent(input: PortableAuditInput,
  policy: SiemExportPolicy = DEFAULT_SIEM_POLICY): PortableAuditEvent {
  if (!identifiers(input.id) || !identifiers(input.organizationId) ||
      !validDate(input.occurredAt))
    throw Error("SIEM_SOURCE_IDENTITY_INVALID");
  const result = redactAuditMetadata(input.metadata, policy);
  const safeAction = typeof input.action === "string" &&
    /^[A-Za-z0-9_.:-]{2,150}$/.test(input.action) ?
    input.action : "UNRECOGNIZED_ACTION";
  const safeResource = typeof input.resourceType === "string" &&
    /^[A-Za-z0-9_.:-]{2,100}$/.test(input.resourceType) ?
    input.resourceType : "UNKNOWN_RESOURCE";
  const reference = input.resourceId && identifiers(input.resourceId) ?
    input.resourceId : null;
  const action = classifyAuditAction(safeAction);
  return {
    schema: "cyberpilot.siem.event.v1",
    eventId: input.id, organizationId: input.organizationId,
    occurredAt: input.occurredAt, actorType: actor(input.actorType),
    actorReference: policy.includeActorReferences && input.actorUserId &&
      identifiers(input.actorUserId) ? sha(input.organizationId + ":" +
      input.actorUserId).slice(0, 24) : null,
    action: safeAction, category: action.category, severity: action.severity,
    resourceType: safeResource,
    resourceReference: policy.includeResourceReferences && reference ?
      policy.resourceReferenceMode === "EXPLICIT" ? reference :
      policy.resourceReferenceMode === "HASH" ? sha(input.organizationId +
      ":" + reference).slice(0, 24) : null : null,
    metadataFields: result.values, redactedFields: result.removed,
    malformedMetadata: result.malformed,
    confidence: result.malformed || safeAction === "UNRECOGNIZED_ACTION" ?
      "MALFORMED" : result.removed ? "PARTIAL" : "PERSISTED",
    source: "CYBERPILOT_PERSISTED_AUDIT",
    actualRemediationProven: false, transmissionVerified: false,
  };
}
export function verifyPortableAuditBatch(organizationId: string,
  events: readonly PortableAuditEvent[]) {
  const issues: string[] = [], ids = new Set<string>();
  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    if (event.organizationId !== organizationId) issues.push("SIEM_CROSS_TENANT");
    if (ids.has(event.eventId)) issues.push("SIEM_DUPLICATE_EVENT");
    ids.add(event.eventId);
    if (event.source !== "CYBERPILOT_PERSISTED_AUDIT" ||
        event.actualRemediationProven !== false ||
        event.transmissionVerified !== false)
      issues.push("SIEM_UNSUPPORTED_ASSURANCE_CLAIM");
    const prev = events[i-1];
    if (prev && (prev.occurredAt > event.occurredAt ||
        prev.occurredAt === event.occurredAt && prev.eventId >= event.eventId))
      issues.push("SIEM_NONMONOTONIC_ORDER");
    if (Object.keys(event.metadataFields).some(key => forbidden.test(key)))
      issues.push("SIEM_METADATA_POLICY_BYPASS");
  }
  return { valid: issues.length === 0, issues: [...new Set(issues)],
    observedEvents: events.length, externallyDelivered: false as const };
}
