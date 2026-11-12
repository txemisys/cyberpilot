import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  previewStalledOsvRuns, markStalledOsvRunUnknown,
} from "../../../../../../lib/assets-osv-run-recovery";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function errorResponse(error: unknown) {
  if (error instanceof WorkInputError) {
    return NextResponse.json({
      code: error.code, error: error.message,
    }, { status: {
      INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
    }[error.code], headers });
  }
  return NextResponse.json({
    error: "OSV schedule incident service unavailable.",
  }, { status: 503, headers });
}
async function scope(slug: string) {
  const { membership, session } = await requireOrganizationAccess(slug);
  return {
    organizationId: membership.organization.id,
    userId: session.user.id, role: membership.role,
  };
}
export async function GET(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const raw: Record<string, unknown> = {};
    for (const [name, value] of request.nextUrl.searchParams) {
      if (raw[name] !== undefined ||
          !["minimumExpiredMinutes", "maximumListed",
            "includeRecentlyClaimed"].includes(name))
        throw new WorkInputError("INVALID",
          "Unknown or duplicate run recovery parameter.");
      if (name === "includeRecentlyClaimed") {
        if (value !== "true" && value !== "false")
          throw new WorkInputError("INVALID", "Invalid recovery option.");
        raw[name] = value === "true";
      } else {
        if (!/^[1-9][0-9]*$/.test(value) ||
            !Number.isSafeInteger(Number(value)))
          throw new WorkInputError("INVALID", "Invalid recovery limit.");
        raw[name] = Number(value);
      }
    }
    return NextResponse.json(
      await previewStalledOsvRuns(current, raw),
      { headers },
    );
  } catch (cause) {
    return errorResponse(cause);
  }
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const current = await scope((await params).slug);
    const declared = request.headers.get("content-length");
    if (declared && (!/^[0-9]+$/.test(declared) ||
        Number(declared) > 8192))
      throw new WorkInputError("INVALID",
        "Run recovery request exceeds 8 KiB.");
    const source = await request.text();
    if (Buffer.byteLength(source, "utf8") > 8192)
      throw new WorkInputError("INVALID",
        "Run recovery request exceeds 8 KiB.");
    let command: unknown;
    try { command = JSON.parse(source); }
    catch { throw new WorkInputError("INVALID", "Invalid recovery JSON."); }
    return NextResponse.json(
      await markStalledOsvRunUnknown(current, command),
      { headers },
    );
  } catch (cause) {
    return errorResponse(cause);
  }
}
