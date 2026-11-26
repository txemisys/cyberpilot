import { createHash } from "node:crypto";

/**
 * Durable 6V–6X coordination ledger. This envelope is intentionally unable
 * to authorize external remediations, tenant-wide identity correlation or
 * receipt of actions taken by a cloud provider.
 */
export type CoordinationKind = "INVESTIGATION" | "CORRELATION" | "SHIFT";
export type CoordinationRole = "OWNER" | "ADMIN" | "AUDITOR";
export type CoordinationState =
  "OPEN" | "ACTIVE" | "PENDING_REVIEW" | "ACCEPTED_INTERNAL" |
  "REJECTED_INTERNAL" | "CLOSED_INTERNAL" | "REOPENED";
export type CoordinationReceipt = {
  schema: "cyberpilot.incident.coordination.event.v1";
  organizationId: string; incidentId: string; recordId: string;
  kind: CoordinationKind; revision: number; commandId: string;
  actorId: string; operation: string; at: string;
  beforeDigest: string | null; afterDigest: string;
  previousEventDigest: string | null; eventDigest: string;
  providerWrites: 0; externallyVerified: false;
};
export type CoordinationEnvelope<T> = {
  schema: "cyberpilot.incident.coordination.record.v1";
  id: string; organizationId: string; incidentId: string;
  kind: CoordinationKind; state: CoordinationState;
  revision: number; sourceDigest: string;
  createdAt: string; updatedAt: string; createdBy: string;
  payload: T; providerWrites: 0; providerOutcomeVerified: false;
};
export type CoordinationCommand<A> = {
  organizationId: string; incidentId: string; recordId: string;
  kind: CoordinationKind; commandId: string;
  expectedRevision: number; actorId: string; role: CoordinationRole;
  at: string; action: A;
};
export type CoordinationHistory<T> = {
  snapshot: CoordinationEnvelope<T>;
  events: CoordinationReceipt[];
  integrity: "VERIFIED_LOCAL" | "CONFLICT";
  providerOutcomesVerified: false;
};
const ident = (x: unknown): x is string =>
  typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const hash = (x: unknown): x is string =>
  typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const timestamp = (x: unknown): x is string =>
  typeof x === "string" && Number.isFinite(Date.parse(x)) &&
  new Date(x).toISOString() === x;
const kinds: CoordinationKind[] = ["INVESTIGATION", "CORRELATION", "SHIFT"];
const states: CoordinationState[] = [
  "OPEN", "ACTIVE", "PENDING_REVIEW", "ACCEPTED_INTERNAL",
  "REJECTED_INTERNAL", "CLOSED_INTERNAL", "REOPENED",
];
function canonical(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(canonical);
  if (x !== null && typeof x === "object") {
    const record = x as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort()
      .filter(k => record[k] !== undefined)
      .map(k => [k, canonical(record[k])]));
  }
  return x;
}
export function coordinationDigest(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(canonical(value))).digest("hex");
}
const fail = (code: string): never => { throw Error(code); };
export function validateCoordinationEnvelope<T>(
  value: CoordinationEnvelope<T>,
): string[] {
  const errors: string[] = [];
  if (!value || value.schema !==
      "cyberpilot.incident.coordination.record.v1")
    errors.push("COORDINATION_SCHEMA_INVALID");
  if (![value?.id, value?.organizationId, value?.incidentId,
    value?.createdBy].every(ident))
    errors.push("COORDINATION_ID_INVALID");
  if (!kinds.includes(value?.kind) || !states.includes(value?.state))
    errors.push("COORDINATION_STATE_INVALID");
  if (!Number.isSafeInteger(value?.revision) ||
      value.revision < 1 || value.revision > 10000)
    errors.push("COORDINATION_REVISION_INVALID");
  if (!hash(value?.sourceDigest))
    errors.push("COORDINATION_SOURCE_DIGEST_INVALID");
  if (!timestamp(value?.createdAt) || !timestamp(value?.updatedAt) ||
      value.updatedAt < value.createdAt)
    errors.push("COORDINATION_TIME_INVALID");
  if (value?.providerWrites !== 0 ||
      value?.providerOutcomeVerified !== false)
    errors.push("COORDINATION_EXTERNAL_CLAIM_FORGED");
  if (!value || !value.payload || typeof value.payload !== "object" ||
      Array.isArray(value.payload))
    errors.push("COORDINATION_PAYLOAD_INVALID");
  return errors;
}
export function validateCoordinationCommand<A>(
  command: CoordinationCommand<A>,
): string[] {
  const errors: string[] = [];
  if (!command || ![command.organizationId, command.incidentId,
      command.recordId, command.commandId, command.actorId].every(ident))
    errors.push("COORDINATION_COMMAND_SCOPE_INVALID");
  if (!kinds.includes(command?.kind) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(command?.role))
    errors.push("COORDINATION_COMMAND_ROLE_INVALID");
  if (!Number.isSafeInteger(command?.expectedRevision) ||
      command.expectedRevision < 1 || command.expectedRevision > 10000)
    errors.push("COORDINATION_COMMAND_REVISION_INVALID");
  if (!timestamp(command?.at))
    errors.push("COORDINATION_COMMAND_TIME_INVALID");
  if (!command || !command.action || typeof command.action !== "object" ||
      Array.isArray(command.action))
    errors.push("COORDINATION_COMMAND_ACTION_INVALID");
  return errors;
}
export function createCoordination<T>(args: {
  id: string; organizationId: string; incidentId: string;
  kind: CoordinationKind; state: CoordinationState;
  sourceDigest: string; actorId: string; at: string; payload: T;
  commandId: string;
}): { snapshot: CoordinationEnvelope<T>; event: CoordinationReceipt } {
  if (![args.id, args.organizationId, args.incidentId,
      args.actorId, args.commandId].every(ident) ||
      !kinds.includes(args.kind) || !states.includes(args.state) ||
      !hash(args.sourceDigest) || !timestamp(args.at))
    fail("COORDINATION_CREATE_INVALID");
  const snapshot: CoordinationEnvelope<T> = {
    schema: "cyberpilot.incident.coordination.record.v1",
    id: args.id, organizationId: args.organizationId,
    incidentId: args.incidentId, kind: args.kind,
    state: args.state, revision: 1, sourceDigest: args.sourceDigest,
    createdAt: args.at, updatedAt: args.at, createdBy: args.actorId,
    payload: args.payload, providerWrites: 0,
    providerOutcomeVerified: false,
  };
  if (validateCoordinationEnvelope(snapshot).length)
    fail("COORDINATION_CREATED_SNAPSHOT_INVALID");
  const afterDigest = coordinationDigest(snapshot);
  const event = makeCoordinationEvent({
    snapshot, beforeDigest: null, afterDigest,
    commandId: args.commandId, actorId: args.actorId,
    at: args.at, operation: "CREATE", previousEventDigest: null,
  });
  return { snapshot, event };
}
export function makeCoordinationEvent<T>(args: {
  snapshot: CoordinationEnvelope<T>;
  beforeDigest: string | null; afterDigest: string;
  commandId: string; actorId: string; at: string;
  operation: string; previousEventDigest: string | null;
}): CoordinationReceipt {
  if (validateCoordinationEnvelope(args.snapshot).length ||
      !ident(args.commandId) || !ident(args.actorId) ||
      !timestamp(args.at) || !/^[A-Z_]{3,48}$/.test(args.operation) ||
      !hash(args.afterDigest) ||
      args.beforeDigest !== null && !hash(args.beforeDigest) ||
      args.previousEventDigest !== null && !hash(args.previousEventDigest))
    fail("COORDINATION_EVENT_INPUT_INVALID");
  const base = {
    schema: "cyberpilot.incident.coordination.event.v1" as const,
    organizationId: args.snapshot.organizationId,
    incidentId: args.snapshot.incidentId,
    recordId: args.snapshot.id,
    kind: args.snapshot.kind, revision: args.snapshot.revision,
    commandId: args.commandId, actorId: args.actorId,
    operation: args.operation, at: args.at,
    beforeDigest: args.beforeDigest, afterDigest: args.afterDigest,
    previousEventDigest: args.previousEventDigest,
    providerWrites: 0 as const, externallyVerified: false as const,
  };
  return { ...base, eventDigest: coordinationDigest(base) };
}
export function evolveCoordination<T, A>(args: {
  current: CoordinationEnvelope<T>; command: CoordinationCommand<A>;
  lastEventDigest: string; nextPayload: T;
  nextState: CoordinationState; operation: string;
}): { snapshot: CoordinationEnvelope<T>; event: CoordinationReceipt } {
  const previous = args.current;
  const command = args.command;
  if (validateCoordinationEnvelope(previous).length ||
      validateCoordinationCommand(command).length)
    fail("COORDINATION_EVOLVE_INVALID");
  if (previous.organizationId !== command.organizationId ||
      previous.incidentId !== command.incidentId ||
      previous.id !== command.recordId || previous.kind !== command.kind)
    fail("COORDINATION_CROSS_TENANT_OR_RECORD");
  if (previous.revision !== command.expectedRevision)
    fail("COORDINATION_CAS_REVISION_CONFLICT");
  if (!hash(args.lastEventDigest) || command.at < previous.updatedAt)
    fail("COORDINATION_EVENT_CLOCK_OR_HASH_INVALID");
  if (previous.revision >= 10000)
    fail("COORDINATION_REVISION_LIMIT");
  if (!states.includes(args.nextState))
    fail("COORDINATION_NEXT_STATE_INVALID");
  const snapshot: CoordinationEnvelope<T> = {
    ...previous, payload: args.nextPayload,
    state: args.nextState, revision: previous.revision + 1,
    updatedAt: command.at, providerWrites: 0,
    providerOutcomeVerified: false,
  };
  if (validateCoordinationEnvelope(snapshot).length)
    fail("COORDINATION_EVOLVED_SNAPSHOT_INVALID");
  const event = makeCoordinationEvent({
    snapshot, beforeDigest: coordinationDigest(previous),
    afterDigest: coordinationDigest(snapshot),
    commandId: command.commandId, actorId: command.actorId,
    at: command.at, operation: args.operation,
    previousEventDigest: args.lastEventDigest,
  });
  return { snapshot, event };
}
export function verifyCoordinationHistory<T>(
  snapshot: CoordinationEnvelope<T>, events: CoordinationReceipt[],
): string[] {
  const issues = validateCoordinationEnvelope(snapshot);
  if (!Array.isArray(events) || events.length !== snapshot?.revision ||
      events.length > 10000) return [...issues, "COORDINATION_HISTORY_LENGTH"];
  const ids = new Set<string>();
  let previous: CoordinationReceipt | null = null;
  for (let i = 0; i < events.length; i++) {
    const row = events[i]!;
    if (row.schema !== "cyberpilot.incident.coordination.event.v1" ||
        row.organizationId !== snapshot.organizationId ||
        row.incidentId !== snapshot.incidentId ||
        row.recordId !== snapshot.id || row.kind !== snapshot.kind)
      issues.push("COORDINATION_HISTORY_SCOPE_INVALID");
    if (row.revision !== i + 1 ||
        !ident(row.commandId) || ids.has(row.commandId))
      issues.push("COORDINATION_HISTORY_REVISION_OR_COMMAND_INVALID");
    ids.add(row.commandId);
    if (row.eventDigest !== coordinationDigest({
      ...row, eventDigest: undefined,
    }) || row.providerWrites !== 0 ||
        row.externallyVerified !== false)
      issues.push("COORDINATION_HISTORY_EVENT_FORGED");
    if (i === 0 && (row.beforeDigest !== null ||
        row.previousEventDigest !== null || row.operation !== "CREATE"))
      issues.push("COORDINATION_HISTORY_ROOT_INVALID");
    if (previous && (row.previousEventDigest !== previous.eventDigest ||
        row.beforeDigest !== previous.afterDigest ||
        row.at < previous.at))
      issues.push("COORDINATION_HISTORY_CHAIN_BROKEN");
    previous = row;
  }
  if (previous?.afterDigest !== coordinationDigest(snapshot))
    issues.push("COORDINATION_HISTORY_TIP_MISMATCH");
  return [...new Set(issues)];
}
export function coordinationAuditExport<T>(
  snapshot: CoordinationEnvelope<T>, events: CoordinationReceipt[],
) {
  const issues = verifyCoordinationHistory(snapshot, events);
  if (issues.length) fail("COORDINATION_EXPORT_DENIED:" + issues.join(","));
  const envelope = {
    schema: "cyberpilot.incident.coordination.audit.v1" as const,
    organizationId: snapshot.organizationId,
    incidentId: snapshot.incidentId,
    recordId: snapshot.id,
    snapshot, events,
    snapshotDigest: coordinationDigest(snapshot),
    lastEventDigest: events.at(-1)!.eventDigest,
    providerProofEstablished: false as const,
  };
  return { ...envelope, envelopeDigest: coordinationDigest(envelope) };
}
export function compareCoordinationSnapshots<T>(
  before: CoordinationEnvelope<T>, after: CoordinationEnvelope<T>,
) {
  if (validateCoordinationEnvelope(before).length ||
      validateCoordinationEnvelope(after).length)
    fail("COORDINATION_COMPARE_INVALID");
  if (before.organizationId !== after.organizationId ||
      before.incidentId !== after.incidentId ||
      before.id !== after.id || before.kind !== after.kind)
    fail("COORDINATION_COMPARE_CROSS_TENANT");
  return {
    schema: "cyberpilot.incident.coordination.diff.v1" as const,
    revisionDelta: after.revision - before.revision,
    stateChanged: before.state !== after.state,
    sourceChanged: before.sourceDigest !== after.sourceDigest,
    payloadChanged: coordinationDigest(before.payload) !==
      coordinationDigest(after.payload),
    previousDigest: coordinationDigest(before),
    currentDigest: coordinationDigest(after),
    providerOutcomeVerified: false as const,
  };
}
