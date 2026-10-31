import { db } from "@cyberpilot/database";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { buildFindingEvidenceReview, evidenceReviewCsv } from "../../../../../../../lib/finding-evidence-review";
import { loadReviewData, parseReviewListOptions } from "../../../../../../../lib/finding-review-data";

/**
 * The export shares the exact tenant-filtered review reader with the UI.
 * Never include raw evidence details or integration tokens in a CSV.
 * Unlike the paged view, exports are complete up to a declared hard limit.
 */
export async function GET(
  request: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const organizationId = membership.organization.id;
  const paramsFromUrl = new URL(request.url).searchParams;
  const settings = parseReviewListOptions(paramsFromUrl);

  const where = {
    organizationId,
    ...(settings.includeResolved ? {} : { status: "OPEN" as const }),
    ...(settings.severity ? { severity: settings.severity } : {}),
    ...(settings.search ? {
      OR: [
        { title: { contains: settings.search, mode: "insensitive" as const } },
        { ruleId: { contains: settings.search, mode: "insensitive" as const } },
        { description: { contains: settings.search, mode: "insensitive" as const } },
      ],
    } : {}),
  };
  const count = await db.securityFinding.count({ where });
  if (count > 500) {
    return new Response(
      "The review includes more than 500 findings. Narrow your filters before exporting.",
      {
        status: 422,
        headers: {
          "Cache-Control": "private, no-store",
          "Content-Type": "text/plain; charset=utf-8",
        },
      },
    );
  }
  if (count === 0) {
    return new Response(evidenceReviewCsv([]), {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="cyberpilot-evidence-review.csv"',
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }

  // Use complete pages with the same normalization and evidence matching as
  // the human-readable review. Do not silently drop findings after page one.
  const findings = [];
  for (let offset = 0; offset < count; offset += 50) {
    const page = await loadReviewData(organizationId, {
      ...settings,
      limit: 50,
      offset,
    });
    findings.push(...page.findings);
  }
  if (findings.length !== count) {
    return new Response(
      "Review data changed during export. Retry to obtain a complete snapshot.",
      {
        status: 409,
        headers: { "Cache-Control": "private, no-store" },
      },
    );
  }

  const reviews = findings.map(buildFindingEvidenceReview);
  const output = evidenceReviewCsv(reviews);
  return new Response(output, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": 'attachment; filename="cyberpilot-evidence-review.csv"',
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
