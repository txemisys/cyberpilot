import { db, type Prisma } from "@cyberpilot/database";
import { buildSnapshotManifest } from "./work-integrity-snapshot-integrity";
import { parseCaseSnapshot, type CaseSnapshot } from "./work-integrity-snapshots";
import {
  planSnapshotIngestion, materializeAcceptedSnapshotBatch,
  type IngestionPlan, type IngestionPolicy,
} from "./work-integrity-snapshot-ingestion";

export type CaptureWriteScope = {
  organizationId: string;
  actorUserId: string;
};
export type StoredCaptureSummary = {
  id: string;
  source: string;
  capturedAt: string;
  complete: boolean;
  caseCount: number;
  digest: string;
  createdAt: string;
};
export const DEFAULT_CAPTURE_POLICY: IngestionPolicy = {
  maxAgeDays: 3650,
  maxFutureSkewMinutes: 5,
  maxCasesPerCapture: 10000,
  maxCapturesPerSource: 1000,
  requireComplete: false,
  rejectQualityBlockers: true,
  rejectQualityWarnings: false,
  allowedSources: null,
};
const MAX_BATCH = 100;
const MAX_HISTORY = 1000;

function scopeCheck(scope: CaptureWriteScope): void {
  if (!scope.organizationId || !scope.actorUserId)
    throw new Error("Authenticated organization and actor are required.");
}
function serialize(capture: CaseSnapshot): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(capture)) as Prisma.InputJsonValue;
}
function stored(row: {
  id: string; source: string; capturedAt: Date; complete: boolean;
  caseCount: number; digest: string; createdAt: Date;
}): StoredCaptureSummary {
  return {
    id: row.id, source: row.source, capturedAt: row.capturedAt.toISOString(),
    complete: row.complete, caseCount: row.caseCount, digest: row.digest,
    createdAt: row.createdAt.toISOString(),
  };
}

/** Every query is explicitly scoped by the authenticated organization. */
export async function listStoredIntegrityCaptures(
  organizationId: string, limit = 50, before?: Date,
): Promise<StoredCaptureSummary[]> {
  if (!organizationId) throw new Error("Organization required.");
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_HISTORY)
    throw new Error("Invalid capture history limit.");
  if (before && !Number.isFinite(before.getTime()))
    throw new Error("Invalid capture history cursor.");
  const rows = await db.integrityCaseCapture.findMany({
    where: {
      organizationId,
      ...(before ? { capturedAt: { lt: before } } : {}),
    },
    orderBy: [{ capturedAt: "desc" }, { id: "desc" }],
    take: limit,
    select: {
      id: true, source: true, capturedAt: true, complete: true,
      caseCount: true, digest: true, createdAt: true,
    },
  });
  return rows.map(stored);
}

/** Never accept a client-provided organization for reading stored payloads. */
export async function readStoredIntegrityCapture(
  organizationId: string, captureId: string,
): Promise<CaseSnapshot | null> {
  if (!organizationId || !captureId) throw new Error("Capture scope required.");
  const row = await db.integrityCaseCapture.findFirst({
    where: { id: captureId, organizationId },
    select: { payload: true, digest: true },
  });
  if (!row) return null;
  const capture = parseCaseSnapshot(row.payload);
  if (capture.organizationId !== organizationId)
    throw new Error("Stored capture violates tenant isolation.");
  const manifest = buildSnapshotManifest([capture], organizationId, new Date().toISOString());
  if (manifest.entries[0].sha256 !== row.digest)
    throw new Error("Stored capture integrity check failed.");
  return capture;
}

/**
 * Preflight is advisory only. The write path repeats it inside a SERIALIZABLE
 * transaction, so concurrent writers cannot rely on a stale acceptance plan.
 */
export async function ingestStoredIntegrityCaptures(
  scope: CaptureWriteScope,
  incomingInput: readonly unknown[],
  policy: IngestionPolicy = DEFAULT_CAPTURE_POLICY,
): Promise<{ plan: IngestionPlan; stored: StoredCaptureSummary[] }> {
  scopeCheck(scope);
  if (!Array.isArray(incomingInput) || incomingInput.length < 1 ||
      incomingInput.length > MAX_BATCH)
    throw new Error("Invalid capture ingestion batch size.");
  const incoming = incomingInput.map(value => parseCaseSnapshot(value));
  if (incoming.some(capture => capture.organizationId !== scope.organizationId))
    throw new Error("Cross-organization capture ingestion forbidden.");
  const sources = [...new Set(incoming.map(capture => capture.source))];
  return db.$transaction(async tx => {
    const existingRows = await tx.integrityCaseCapture.findMany({
      where: { organizationId: scope.organizationId, source: { in: sources } },
      select: { payload: true },
    });
    if (existingRows.length > 10000)
      throw new Error("Capture history exceeds bounded ingestion capacity.");
    const existing = existingRows.map(row => parseCaseSnapshot(row.payload));
    const evaluatedAt = new Date().toISOString();
    const plan = planSnapshotIngestion(
      incoming, existing, scope.organizationId, evaluatedAt, policy,
    );
    if (plan.rejected > 0)
      throw new Error("Capture ingestion rejected by policy; no captures persisted.");
    const batch = materializeAcceptedSnapshotBatch(plan, incoming);
    const hashes = batch.expectedDigestByIdentity;
    const created: StoredCaptureSummary[] = [];
    for (const capture of batch.accepted) {
      const key = JSON.stringify([capture.source, Date.parse(capture.capturedAt)]);
      const digest = hashes[key];
      if (!digest) throw new Error("Missing planned capture digest.");
      const row = await tx.integrityCaseCapture.create({
        data: {
          organizationId: scope.organizationId,
          createdById: scope.actorUserId,
          source: capture.source,
          capturedAt: new Date(capture.capturedAt),
          complete: capture.complete,
          caseCount: capture.cases.length,
          digest,
          payload: serialize(capture),
        },
      });
      created.push(stored(row));
    }
    if (created.length > 0) {
      await tx.auditEvent.create({
        data: {
          organizationId: scope.organizationId,
          actorType: "USER",
          actorUserId: scope.actorUserId,
          action: "INTEGRITY_CAPTURES_INGESTED",
          resourceType: "INTEGRITY_CASE_CAPTURE",
          metadata: {
            captureIds: created.map(item => item.id),
            digests: created.map(item => item.digest),
            sources: created.map(item => item.source),
            count: created.length,
          },
        },
      });
    }
    return { plan, stored: created };
  }, { isolationLevel: "Serializable", timeout: 30000 });
}
