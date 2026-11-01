import type { CaseRow } from "./work-integrity-cases";
import type { CaseSnapshot } from "./work-integrity-snapshots";
import { buildReviewWorklist } from "./work-integrity-worklist";

/** Immutable analyst handoff manifests; no access or mutation is performed. */
export type HandoffRecipient = { id: string; capacity: number; codes: string[]; workItemIds: string[] };
export type HandoffPolicy = {
  recipients: HandoffRecipient[];
  includeReviewed: boolean;
  includeHistorical: boolean;
  requireCompleteCoverage: boolean;
  allowUnassigned: boolean;
};
export type HandoffItem = {
  key: string;
  workItemId: string;
  code: string;
  resourceId: string;
  priority: string;
  revision: number;
  reviewEventId: string | null;
  recipientId: string | null;
  rationale: string;
};
export type HandoffManifest = {
  version: 1;
  organizationId: string;
  capturedAt: string;
  sourceComplete: boolean;
  items: HandoffItem[];
  unassigned: string[];
  recipientLoads: Record<string, number>;
  warnings: string[];
};
export type HandoffAudit = {
  valid: boolean;
  violations: string[];
  totalItems: number;
  assignedItems: number;
  unassignedItems: number;
  capacityUtilization: Array<{ recipientId: string; assigned: number; capacity: number; utilization: number }>;
};
function assertId(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.length > 200 ||
      /[\u0000-\u001f\u007f]/.test(value))
    throw new Error(`Invalid ${label}.`);
}
function assertList(values: unknown, label: string): asserts values is string[] {
  if (!Array.isArray(values) || values.length > 10000 ||
      values.some(x => typeof x !== "string" || !x.trim() || x.length > 200))
    throw new Error(`Invalid ${label}.`);
}
export function validateHandoffPolicy(policy: HandoffPolicy): HandoffPolicy {
  if (!policy || !Array.isArray(policy.recipients) ||
      policy.recipients.length < 1 || policy.recipients.length > 100)
    throw new Error("Handoff requires 1–100 recipients.");
  if (typeof policy.includeReviewed !== "boolean" ||
      typeof policy.includeHistorical !== "boolean" ||
      typeof policy.requireCompleteCoverage !== "boolean" ||
      typeof policy.allowUnassigned !== "boolean")
    throw new Error("Invalid handoff policy flags.");
  const ids = new Set<string>();
  const recipients = policy.recipients.map(recipient => {
    assertId(recipient.id, "recipient ID");
    if (ids.has(recipient.id)) throw new Error("Duplicate recipient ID.");
    ids.add(recipient.id);
    if (!Number.isSafeInteger(recipient.capacity) || recipient.capacity < 0 ||
        recipient.capacity > 10000)
      throw new Error("Invalid recipient capacity.");
    assertList(recipient.codes, "recipient codes");
    assertList(recipient.workItemIds, "recipient work items");
    return { ...recipient, codes: [...new Set(recipient.codes)].sort(),
      workItemIds: [...new Set(recipient.workItemIds)].sort() };
  });
  return { ...policy, recipients: recipients.sort((a, b) => a.id.localeCompare(b.id)) };
}
export function recipientEligible(row: CaseRow, recipient: HandoffRecipient): boolean {
  return (recipient.codes.length === 0 || recipient.codes.includes(row.code)) &&
    (recipient.workItemIds.length === 0 || recipient.workItemIds.includes(row.workItemId));
}
export function buildHandoffManifest(snapshot: CaseSnapshot, input: HandoffPolicy): HandoffManifest {
  const policy = validateHandoffPolicy(input);
  const rows = new Map(snapshot.cases.map(row => [row.key, row]));
  const queue = buildReviewWorklist(snapshot).entries.filter(entry => {
    const row = rows.get(entry.caseKey)!;
    return (policy.includeReviewed || row.reviewEventId === null) &&
      (policy.includeHistorical || !row.historicalOnly) &&
      (!policy.requireCompleteCoverage || row.completeCoverage);
  });
  const recipientLoads = Object.fromEntries(policy.recipients.map(r => [r.id, 0])) as Record<string, number>;
  const items: HandoffItem[] = [];
  const unassigned: string[] = [];
  for (const entry of queue) {
    const row = rows.get(entry.caseKey)!;
    const candidate = policy.recipients.filter(recipient =>
      recipientEligible(row, recipient) && recipientLoads[recipient.id]! < recipient.capacity)
      .sort((a, b) => {
        const left = recipientLoads[a.id]! / Math.max(1, a.capacity);
        const right = recipientLoads[b.id]! / Math.max(1, b.capacity);
        return left - right || a.id.localeCompare(b.id);
      })[0];
    if (candidate) recipientLoads[candidate.id]!++;
    else unassigned.push(entry.caseKey);
    items.push({
      key: entry.caseKey, workItemId: row.workItemId, code: row.code,
      resourceId: row.resourceId, priority: entry.priority,
      revision: row.taskRevision, reviewEventId: row.reviewEventId,
      recipientId: candidate?.id ?? null,
      rationale: candidate ? "Eligible recipient with lowest proportional capacity utilization."
        : "No eligible recipient has remaining capacity.",
    });
  }
  if (unassigned.length && !policy.allowUnassigned)
    throw new Error("Handoff cannot satisfy all recipient capacity and eligibility constraints.");
  return {
    version: 1, organizationId: snapshot.organizationId,
    capturedAt: snapshot.capturedAt, sourceComplete: snapshot.complete,
    items, unassigned, recipientLoads,
    warnings: [
      "This is a planning artifact, not an authorization or a completed review.",
      ...(!snapshot.complete ? ["Source collection is incomplete."] : []),
      ...(unassigned.length ? ["Some cases could not be assigned."] : []),
    ],
  };
}
export function auditHandoffManifest(
  manifest: HandoffManifest, snapshot: CaseSnapshot, input: HandoffPolicy,
): HandoffAudit {
  const policy = validateHandoffPolicy(input);
  const violations: string[] = [];
  if (manifest.organizationId !== snapshot.organizationId)
    violations.push("Organization mismatch.");
  if (manifest.capturedAt !== snapshot.capturedAt)
    violations.push("Capture timestamp mismatch.");
  if (manifest.version !== 1) violations.push("Unsupported manifest version.");
  const rows = new Map(snapshot.cases.map(row => [row.key, row]));
  const recipients = new Map(policy.recipients.map(recipient => [recipient.id, recipient]));
  const loads = Object.fromEntries(policy.recipients.map(recipient => [recipient.id, 0])) as Record<string, number>;
  const keys = new Set<string>();
  for (const item of manifest.items) {
    if (keys.has(item.key)) violations.push(`Duplicate handoff case ${item.key}.`);
    keys.add(item.key);
    const row = rows.get(item.key);
    if (!row) {
      violations.push(`Unknown handoff case ${item.key}.`);
      continue;
    }
    if (item.workItemId !== row.workItemId || item.code !== row.code ||
        item.resourceId !== row.resourceId || item.revision !== row.taskRevision ||
        item.reviewEventId !== row.reviewEventId)
      violations.push(`Stale or altered case identity ${item.key}.`);
    if (item.recipientId !== null) {
      const recipient = recipients.get(item.recipientId);
      if (!recipient) violations.push(`Unknown recipient ${item.recipientId}.`);
      else {
        loads[recipient.id]!++;
        if (!recipientEligible(row, recipient))
          violations.push(`Recipient is not eligible for ${item.key}.`);
      }
    }
  }
  for (const recipient of policy.recipients) {
    if (loads[recipient.id]! > recipient.capacity)
      violations.push(`Capacity exceeded for ${recipient.id}.`);
    if (manifest.recipientLoads[recipient.id] !== loads[recipient.id])
      violations.push(`Reported load mismatch for ${recipient.id}.`);
  }
  const unassigned = manifest.items.filter(item => item.recipientId === null)
    .map(item => item.key).sort();
  if (JSON.stringify(unassigned) !== JSON.stringify([...manifest.unassigned].sort()))
    violations.push("Unassigned case inventory mismatch.");
  if (unassigned.length && !policy.allowUnassigned)
    violations.push("Unassigned cases violate the policy.");
  return {
    valid: violations.length === 0, violations, totalItems: manifest.items.length,
    assignedItems: manifest.items.length - unassigned.length,
    unassignedItems: unassigned.length,
    capacityUtilization: policy.recipients.map(recipient => ({
      recipientId: recipient.id, assigned: loads[recipient.id]!,
      capacity: recipient.capacity,
      utilization: recipient.capacity === 0 ? 0 : loads[recipient.id]! / recipient.capacity,
    })),
  };
}
export type HandoffDrift = {
  added: string[];
  removed: string[];
  reassigned: Array<{ key: string; from: string | null; to: string | null }>;
  revisionChanged: string[];
  unchanged: number;
  indeterminate: boolean;
};
export function compareHandoffManifests(
  before: HandoffManifest, after: HandoffManifest,
): HandoffDrift {
  if (before.organizationId !== after.organizationId)
    throw new Error("Cannot compare handoffs from different organizations.");
  const old = new Map(before.items.map(item => [item.key, item]));
  const current = new Map(after.items.map(item => [item.key, item]));
  const added: string[] = [], removed: string[] = [];
  const reassigned: HandoffDrift["reassigned"] = [], revisionChanged: string[] = [];
  let unchanged = 0;
  for (const [key, item] of old) {
    const next = current.get(key);
    if (!next) { removed.push(key); continue; }
    if (item.recipientId !== next.recipientId)
      reassigned.push({ key, from: item.recipientId, to: next.recipientId });
    if (item.revision !== next.revision || item.reviewEventId !== next.reviewEventId)
      revisionChanged.push(key);
    if (item.recipientId === next.recipientId && item.revision === next.revision &&
        item.reviewEventId === next.reviewEventId) unchanged++;
  }
  for (const key of current.keys()) if (!old.has(key)) added.push(key);
  return {
    added: added.sort(), removed: removed.sort(),
    reassigned: reassigned.sort((a, b) => a.key.localeCompare(b.key)),
    revisionChanged: revisionChanged.sort(), unchanged,
    indeterminate: !before.sourceComplete || !after.sourceComplete,
  };
}
export function handoffCsv(manifest: HandoffManifest): string {
  const cell = (value: unknown) => {
    const raw = String(value ?? "");
    const safe = /^[\s\u0000-\u001f]*[=+@\-]/.test(raw) ? "'" + raw : raw;
    return '"' + safe.replace(/"/g, '""') + '"';
  };
  const lines = [[
    "key", "workItemId", "code", "resourceId", "priority",
    "revision", "reviewEventId", "recipientId", "rationale",
  ].map(cell).join(",")];
  for (const item of manifest.items)
    lines.push([
      item.key, item.workItemId, item.code, item.resourceId, item.priority,
      item.revision, item.reviewEventId, item.recipientId, item.rationale,
    ].map(cell).join(","));
  return lines.join("\r\n") + "\r\n";
}
