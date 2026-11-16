import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  ExecutionLedgerError, ExposureExecutionLedgerService,
} from "../../../../../lib/exposure-execution-ledger-service";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function rejected(code: string, status: number) {
  return NextResponse.json({
    code, consumedQuotas: 0, executableLeaseIssued: false,
    startedNetworkCalls: 0, legalApprovalSigned: false,
    historicalCyberScoreModified: false,
  }, { status, headers });
}
export async function POST(request: NextRequest, context: Context) {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin)
    return rejected("CROSS_ORIGIN_DENIED", 403);
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    return rejected("JSON_REQUIRED", 415);
  const length = request.headers.get("content-length");
  if (length && (!/^\d+$/.test(length) || Number(length) > 4096))
    return rejected("BODY_TOO_LARGE", 413);
  try {
    const { membership, session } = await requireOrganizationAccess(
      (await context.params).slug,
    );
    if (!["OWNER","ADMIN","AUDITOR"].includes(membership.role))
      return rejected("REVIEW_ROLE_REQUIRED", 403);
    const raw = await request.text();
    if (Buffer.byteLength(raw) > 4096)
      return rejected("BODY_TOO_LARGE", 413);
    let command: unknown;
    try { command = JSON.parse(raw); }
    catch { return rejected("MALFORMED_JSON", 400); }
    if (!command || typeof command !== "object" ||
        Array.isArray(command))
      return rejected("COMMAND_REQUIRED", 400);
    const fields = command as Record<string, unknown>;
    if (Object.keys(fields).some(k =>
      !["operation","limit","leaseId"].includes(k)))
      return rejected("UNEXPECTED_COMMAND_FIELD", 400);
    if (!["LIST","READ"].includes(fields.operation as string))
      return rejected("READ_ONLY_LEDGER", 405);
    const service = new ExposureExecutionLedgerService();
    const actor = {
      organizationId: membership.organization.id,
      userId: session.user.id, role: membership.role,
    };
    const data = fields.operation === "LIST" ?
      await service.list(actor, fields.limit === undefined ?
        100 : fields.limit as number) :
      await service.read(actor, fields.leaseId as string);
    return NextResponse.json({
      schema: "cyberpilot.exposure.execution.ledger.api.v1",
      organizationId: membership.organization.id,
      data,
      consumedQuotas: 0, executableLeaseIssued: false,
      startedNetworkCalls: 0, legalApprovalSigned: false,
      historicalCyberScoreModified: false,
    }, { headers });
  } catch (cause) {
    if (cause instanceof ExecutionLedgerError)
      return rejected(cause.code, 400);
    return rejected("LEDGER_READ_UNAVAILABLE", 503);
  }
}
export async function GET() {
  return rejected("POST_ONLY", 405);
}
export async function PATCH() {
  return rejected("OPERATOR_ONLY_MUTATION", 405);
}
export async function DELETE() {
  return rejected("LEDGER_IS_IMMUTABLE", 405);
}
