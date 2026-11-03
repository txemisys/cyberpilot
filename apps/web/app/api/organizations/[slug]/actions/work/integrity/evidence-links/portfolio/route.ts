import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import { parseIntegrityEvidenceCoveragePolicy } from "../../../../../../../../../lib/work-integrity-evidence-coverage";
import {
  parseIntegrityEvidencePortfolioInput,
  parseIntegrityEvidencePortfolioQuery,
  buildIntegrityEvidencePortfolio,
  queryIntegrityEvidencePortfolio,
  buildIntegrityPortfolioAtCheckpoints,
} from "../../../../../../../../../lib/work-integrity-evidence-portfolio";
import {
  parseIntegrityPortfolioRiskWeights,
  parseIntegrityPortfolioRiskQuery,
  analyzeIntegrityPortfolioRisk,
  queryIntegrityPortfolioRisk,
} from "../../../../../../../../../lib/work-integrity-portfolio-risk";
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity portfolio evaluation failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({
    error: "Unable to evaluate integrity evidence portfolio.",
  }, { status: 500, headers });
}
function parseRequest(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected portfolio request object.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(x => ![
    "portfolio", "view", "query", "weights", "checkpoints",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown portfolio request field.");
  const portfolio = parseIntegrityEvidencePortfolioInput(raw.portfolio);
  const policies = portfolio.policies.map(x => parseIntegrityEvidenceCoveragePolicy(x));
  const view = raw.view ?? "summary";
  if (typeof view !== "string")
    throw new WorkInputError("INVALID", "Invalid portfolio view.");
  if (!["summary", "cases", "risk", "risk-page", "history"].includes(view))
    throw new WorkInputError("INVALID", "Unknown portfolio view.");
  if (view !== "history" && raw.checkpoints !== undefined)
    throw new WorkInputError("INVALID", "Checkpoints require history view.");
  if (view !== "risk" && view !== "risk-page" && raw.weights !== undefined)
    throw new WorkInputError("INVALID", "Risk weights require risk view.");
  if (!["cases", "risk-page"].includes(view) && raw.query !== undefined)
    throw new WorkInputError("INVALID", "Query filters require paginated view.");
  return {
    portfolio: { ...portfolio, policies },
    view, query: raw.query, weights: raw.weights,
    checkpoints: raw.checkpoints,
  };
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    if (!/^application\/json(?:\s*;|\s*$)/i.test(
      request.headers.get("content-type") ?? ""))
      throw new WorkInputError("INVALID", "JSON content type required.");
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) || Number(length) > 100000))
      throw new WorkInputError("INVALID", "Portfolio request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Portfolio request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const parsed = parseRequest(input);
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, parsed.portfolio.captureId);
    if (parsed.view === "history") {
      if (!Array.isArray(parsed.checkpoints))
        throw new WorkInputError("INVALID", "History checkpoints required.");
      const result = buildIntegrityPortfolioAtCheckpoints(
        parsed.portfolio, state.events, parsed.checkpoints);
      return NextResponse.json({ result }, { headers });
    }
    const portfolio = buildIntegrityEvidencePortfolio(
      parsed.portfolio, state.events);
    if (parsed.view === "summary")
      return NextResponse.json({ portfolio }, { headers });
    if (parsed.view === "cases") {
      const query = parseIntegrityEvidencePortfolioQuery(parsed.query ?? {});
      const result = queryIntegrityEvidencePortfolio(portfolio, query);
      return NextResponse.json({ result }, { headers });
    }
    const weights = parseIntegrityPortfolioRiskWeights(parsed.weights);
    const risk = analyzeIntegrityPortfolioRisk(portfolio, weights);
    if (parsed.view === "risk")
      return NextResponse.json({ risk }, { headers });
    const query = parseIntegrityPortfolioRiskQuery(parsed.query ?? {});
    const result = queryIntegrityPortfolioRisk(risk, query);
    return NextResponse.json({ result }, { headers });
  } catch (error) { return failure(error); }
}
