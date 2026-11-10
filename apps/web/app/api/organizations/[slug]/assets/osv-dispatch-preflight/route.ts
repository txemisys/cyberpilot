import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  inspectOsvDispatchPreflight, simulateSignedDispatchChallenge,
} from "../../../../../../lib/assets-osv-dispatch-preflight";
import {
  configuredDispatchKeys,
} from "../../../../../../lib/assets-osv-signed-dispatch";
import { WorkInputError, canManageWork } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(cause: unknown) {
  if (cause instanceof WorkInputError)
    return NextResponse.json({
      error: cause.message, code: cause.code,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403,
      MISSING: 404, CONFLICT: 409,
    }[cause.code], headers });
  return NextResponse.json({
    error: "Signed dispatch preflight is temporarily unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { membership, session } = await requireOrganizationAccess(slug);
  if (!canManageWork(membership.role))
    throw new WorkInputError("FORBIDDEN",
      "Only an organization administrator may inspect signed dispatch.");
  return {
    organizationId: membership.organization.id,
    userId: session.user.id,
    role: membership.role,
  };
}
async function parseBody(request: NextRequest) {
  if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
      "application/json")
    throw new WorkInputError("INVALID",
      "Signed dispatch preflight requires JSON.");
  const size = request.headers.get("content-length");
  if (size && (!/^[0-9]+$/.test(size) || Number(size) > 8192))
    throw new WorkInputError("INVALID", "Preflight body exceeds 8 KiB.");
  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > 8192)
    throw new WorkInputError("INVALID", "Preflight body exceeds 8 KiB.");
  try { return JSON.parse(text) as unknown; }
  catch { throw new WorkInputError("INVALID",
    "Preflight JSON must parse successfully."); }
}
export async function GET(_request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    return NextResponse.json(await inspectOsvDispatchPreflight(
      current), { headers });
  } catch (cause) { return failure(cause); }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const input = await parseBody(request);
    return NextResponse.json(await inspectOsvDispatchPreflight(
      current, input), { headers });
  } catch (cause) { return failure(cause); }
}
export async function PUT(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const value = await parseBody(request);
    if (!value || typeof value !== "object" ||
        Array.isArray(value))
      throw new WorkInputError("INVALID", "Challenge must be an object.");
    const command = value as Record<string, unknown>;
    if (Object.keys(command).some(key => ![
      "scheduleId", "expectedRevision", "keyId",
    ].includes(key)))
      throw new WorkInputError("INVALID",
        "Unexpected signed dispatch challenge field.");
    if (typeof command.scheduleId !== "string" ||
        !/^[A-Za-z0-9_-]{8,150}$/.test(command.scheduleId) ||
        typeof command.expectedRevision !== "number" ||
        !Number.isSafeInteger(command.expectedRevision) ||
        command.expectedRevision < 1 ||
        command.expectedRevision > 10000000 ||
        (command.keyId !== undefined &&
          (typeof command.keyId !== "string" ||
          !/^[A-Za-z0-9_-]{8,100}$/.test(command.keyId))))
      throw new WorkInputError("INVALID",
        "Invalid signed dispatch challenge parameters.");
    const summary = await inspectOsvDispatchPreflight(current, {
      scheduleId: command.scheduleId,
    });
    const schedule = summary.schedules[0];
    if (!schedule || schedule.revision !== command.expectedRevision)
      throw new WorkInputError("CONFLICT",
        "Schedule revision changed since preflight.");
    const challenge = simulateSignedDispatchChallenge(
      current.organizationId,
      schedule.scheduleId, schedule.revision,
      configuredDispatchKeys(), new Date(),
      command.keyId as string | undefined);
    return NextResponse.json({
      ...challenge,
      preflightDigest: summary.digest,
      preflightBlocked: schedule.blocked > 0,
      warnings: [
        ...challenge.warnings,
        "A cryptographic challenge never submits a dispatch or persists nonce material.",
        "An accepted challenge cannot override a blocked operational preflight.",
      ],
    }, { headers });
  } catch (cause) { return failure(cause); }
}
