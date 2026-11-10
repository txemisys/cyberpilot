import { NextRequest, NextResponse } from "next/server";
import {
  configuredDispatchKeys, verifySignedDispatch,
  executeSignedOsvDispatch,
} from "../../../../../lib/assets-osv-signed-dispatch";
import { WorkInputError } from "../../../../../lib/remediation-work-input";

const headers = {
  "Cache-Control": "private, no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
};
const no = (status: number, code: string, error: string) =>
  NextResponse.json({ code, error }, { status, headers });
/**
 * This is NOT a public webhook. An operator must explicitly enable it via
 * environment configuration and install per-tenant 256-bit HMAC secrets.
 * It accepts no browser session and never installs a poller or cron.
 */
export async function POST(request: NextRequest) {
  try {
    const keys = configuredDispatchKeys();
    if (!keys.enabled)
      return no(404, "DISABLED",
        "Signed OSV service dispatch is not enabled.");
    if (request.headers.get("content-type")?.split(";")[0]?.trim() !==
        "application/json")
      return no(415, "INVALID", "Signed OSV requests require JSON.");
    const declared = request.headers.get("content-length");
    if (declared && (!/^[0-9]+$/.test(declared) ||
        Number(declared) > 4096))
      return no(413, "INVALID", "Signed request exceeds 4 KiB.");
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > 4096)
      return no(413, "INVALID", "Signed request exceeds 4 KiB.");
    let input: unknown;
    try { input = JSON.parse(body); }
    catch { return no(400, "INVALID", "Invalid signed JSON body."); }
    const keyId = request.headers.get("x-cyberpilot-osv-key-id");
    const signature = request.headers.get("x-cyberpilot-osv-signature");
    const verified = verifySignedDispatch(
      input, keyId, signature, keys, new Date());
    const report = await executeSignedOsvDispatch(verified);
    return NextResponse.json(report, { status: 201, headers });
  } catch (cause) {
    if (cause instanceof WorkInputError) {
      return no({
        INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409,
      }[cause.code], cause.code, cause.message);
    }
    // Keep network provider errors and internal credential details hidden.
    return no(503, "UNAVAILABLE", "Signed dispatcher is unavailable.");
  }
}
export async function GET() {
  return no(405, "METHOD_NOT_ALLOWED",
    "Signed OSV dispatch accepts POST only.");
}
