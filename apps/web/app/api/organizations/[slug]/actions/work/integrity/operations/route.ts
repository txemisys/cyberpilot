import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../lib/remediation-work-input";
import { buildSnapshotCatalog } from "../../../../../../../../lib/work-integrity-snapshot-catalog";
import { buildSnapshotManifest, verifySnapshotManifest } from "../../../../../../../../lib/work-integrity-snapshot-integrity";
import { selectSnapshotBaseline, compareLatestCapturesBySource } from "../../../../../../../../lib/work-integrity-snapshot-baselines";
import { detectSnapshotIncidents } from "../../../../../../../../lib/work-integrity-snapshot-incidents";
import { planSnapshotArchive, partitionSnapshotArchive } from "../../../../../../../../lib/work-integrity-snapshot-archive";
import { planSnapshotRecovery, simulateSnapshotRecovery } from "../../../../../../../../lib/work-integrity-snapshot-recovery";
import { assessSnapshotReleaseBatch } from "../../../../../../../../lib/work-integrity-snapshot-release";
import { buildSnapshotReviewLedger } from "../../../../../../../../lib/work-integrity-snapshot-reviews";
import { planSnapshotIngestion, materializeAcceptedSnapshotBatch } from "../../../../../../../../lib/work-integrity-snapshot-ingestion";
import { buildCaseContinuityReport } from "../../../../../../../../lib/work-integrity-case-continuity";
import { exportSnapshotReport, type SnapshotCsvKind } from "../../../../../../../../lib/work-integrity-snapshot-exports";
import { buildSnapshotTrendReport } from "../../../../../../../../lib/work-integrity-snapshot-trends";
import { planSnapshotRetention } from "../../../../../../../../lib/work-integrity-snapshot-retention";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BYTES = 5_000_000;
const MAX_CAPTURES = 1000;
type RecordValue = Record<string, unknown>;
function object(value: unknown, label: string): RecordValue {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", `Expected ${label} object.`);
  return value as RecordValue;
}
function list(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value) || value.length > MAX_CAPTURES)
    throw new WorkInputError("INVALID", `Invalid ${label} collection.`);
  return value;
}
function string(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim() || value.length > 1000)
    throw new WorkInputError("INVALID", `Invalid ${label}.`);
  return value;
}
function policy(value: unknown): RecordValue {
  return object(value, "policy");
}
async function boundedJson(request: NextRequest): Promise<RecordValue> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|\s*$)/i.test(contentType))
    throw new WorkInputError("INVALID", "JSON content type required.");
  const lengthHeader = request.headers.get("content-length");
  if (lengthHeader !== null &&
    (!/^\d+$/.test(lengthHeader) || Number(lengthHeader) > MAX_BYTES))
    throw new WorkInputError("INVALID", "Request body exceeds limit.");
  const reader = request.body?.getReader();
  if (!reader) throw new WorkInputError("INVALID", "Missing JSON request body.");
  let length = 0;
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BYTES)
        throw new WorkInputError("INVALID", "Request body exceeds limit.");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let position = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, position);
    position += chunk.byteLength;
  }
  try {
    return object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), "request");
  } catch (error) {
    if (error instanceof WorkInputError) throw error;
    throw new WorkInputError("INVALID", "Malformed UTF-8 JSON request.");
  }
}
const operations = new Set([
  "catalog", "manifest", "verify-manifest", "baseline", "compare-latest",
  "incidents", "archive-plan", "archive-partitions", "recovery-plan",
  "recovery-simulate", "release-batch", "review-ledger", "retention-plan", "trends", "continuity", "ingestion-plan", "ingestion-materialize",
]);
/**
 * Read-only, tenant-scoped offline integrity operations.
 *
 * Uploaded snapshots are untrusted input. The tenant identity is always
 * resolved from authenticated membership, not request JSON.
 * These operations never persist reviews, modify findings or delete evidence.
 */
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { session, membership } = await requireOrganizationAccess(slug);
    if (!session.user.id || !canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Work review access required.");
    const query = request.nextUrl.searchParams;
    if ([...query.keys()].some(key => key !== "format") || query.getAll("format").length > 1)
      throw new WorkInputError("INVALID", "Unexpected query parameters.");
    const format = query.get("format") ?? "json";
    if (format !== "json" && format !== "csv")
      throw new WorkInputError("INVALID", "Unsupported response format.");
    const input = await boundedJson(request);
    const operation = string(input.operation, "operation");
    if (!operations.has(operation))
      throw new WorkInputError("INVALID", "Unsupported integrity operation.");
    const organizationId = membership.organization.id;
    const captures = list(input.captures, "captures");
    const now = new Date().toISOString();
    let result: unknown;
    try {
      switch (operation) {
        case "catalog":
          result = buildSnapshotCatalog(captures, organizationId,
            (input.filter ?? {}) as Parameters<typeof buildSnapshotCatalog>[2]);
          break;
        case "manifest":
          result = buildSnapshotManifest(captures, organizationId, now);
          break;
        case "verify-manifest":
          result = verifySnapshotManifest(
            input.manifest as Parameters<typeof verifySnapshotManifest>[0],
            captures);
          if (object(input.manifest, "manifest").organizationId !== organizationId)
            throw new Error("Cross-organization manifest verification forbidden.");
          break;
        case "baseline":
          result = selectSnapshotBaseline(captures, input.target,
            organizationId, policy(input.policy) as unknown as Parameters<typeof selectSnapshotBaseline>[3]);
          break;
        case "compare-latest":
          result = compareLatestCapturesBySource(captures, organizationId);
          break;
        case "incidents":
          result = detectSnapshotIncidents(captures, organizationId,
            policy(input.policy) as unknown as Parameters<typeof detectSnapshotIncidents>[2]);
          break;
        case "archive-plan":
          result = planSnapshotArchive(captures, organizationId, now,
            policy(input.policy) as unknown as Parameters<typeof planSnapshotArchive>[3]);
          break;
        case "archive-partitions":
          result = partitionSnapshotArchive(captures, organizationId,
            input.maxPartitionBytes as number | undefined);
          break;
        case "recovery-plan":
          result = planSnapshotRecovery(
            input.manifest as Parameters<typeof planSnapshotRecovery>[0],
            list(input.trustedSnapshots, "trusted snapshots"),
            captures, organizationId,
            policy(input.policy) as unknown as Parameters<typeof planSnapshotRecovery>[4]);
          break;
        case "recovery-simulate":
          if (object(input.plan, "plan").organizationId !== organizationId ||
              object(input.manifest, "manifest").organizationId !== organizationId)
            throw new Error("Cross-organization recovery simulation forbidden.");
          result = simulateSnapshotRecovery(
            input.plan as Parameters<typeof simulateSnapshotRecovery>[0],
            captures,
            input.manifest as Parameters<typeof simulateSnapshotRecovery>[2]);
          break;
        case "release-batch":
          result = assessSnapshotReleaseBatch(captures, organizationId, now,
            policy(input.policy) as unknown as Parameters<typeof assessSnapshotReleaseBatch>[3]);
          break;
        case "review-ledger":
          result = buildSnapshotReviewLedger(captures,
            list(input.events, "review events") as Parameters<typeof buildSnapshotReviewLedger>[1],
            organizationId);
          break;
        case "ingestion-plan":
          result = planSnapshotIngestion(captures,
            list(input.existingCaptures, "existing captures"), organizationId, now,
            policy(input.policy) as unknown as Parameters<typeof planSnapshotIngestion>[4]);
          break;
        case "ingestion-materialize":
          if (object(input.plan, "plan").organizationId !== organizationId)
            throw new Error("Cross-organization ingestion materialization forbidden.");
          result = materializeAcceptedSnapshotBatch(
            input.plan as Parameters<typeof materializeAcceptedSnapshotBatch>[0], captures);
          break;
        case "continuity":
          result = buildCaseContinuityReport(captures, organizationId,
            policy(input.policy) as unknown as Parameters<typeof buildCaseContinuityReport>[2]);
          break;
        case "trends":
          result = buildSnapshotTrendReport(captures, organizationId, now,
            policy(input.policy) as unknown as Parameters<typeof buildSnapshotTrendReport>[3]);
          break;
        case "retention-plan":
          result = planSnapshotRetention(captures, organizationId, now,
            policy(input.policy) as unknown as Parameters<typeof planSnapshotRetention>[3]);
          break;
      }
    } catch (error) {
      throw new WorkInputError("INVALID",
        error instanceof Error ? error.message : "Invalid integrity operation input.");
    }
    if (format === "csv") {
      if (!["catalog", "trends", "incidents", "release-batch", "continuity"].includes(operation))
        throw new WorkInputError("INVALID", "CSV export is unsupported for this operation.");
      return new NextResponse(exportSnapshotReport(operation as SnapshotCsvKind, result), {
        headers: { ...headers, "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": 'attachment; filename="integrity-snapshot-report.csv"' },
      });
    }
    return NextResponse.json({
      operation, organizationId, evaluatedAt: now, result,
      limitations: [
        "All uploaded captures and manifests are caller-supplied and are not authenticated.",
        "No persistent data is modified by this endpoint.",
        "Operational diagnostic changes do not establish security control effectiveness.",
      ],
    }, { headers });
  } catch (error) {
    if (error instanceof WorkInputError) {
      const status = error.code === "FORBIDDEN" ? 403 :
        error.code === "MISSING" ? 404 : error.code === "CONFLICT" ? 409 : 400;
      return NextResponse.json({ code: error.code, error: error.message },
        { status, headers });
    }
    console.error("Snapshot operations failed",
      error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Unable to analyze snapshot operations." },
      { status: 500, headers });
  }
}
