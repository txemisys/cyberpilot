import { db } from "@cyberpilot/database";
import {
  getMicrosoftGraphScannerConfiguration,
  isMicrosoftRemediationExecutorConfigured,
} from "@cyberpilot/integrations/microsoft-365";
import Link from "next/link";

import { buildPilotReadiness } from "../../../../lib/pilot-readiness";
import { requireOrganizationAccess } from "../../../../lib/organizations";

type PilotPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

function getProbeResult(metadata: unknown) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return null;
  }

  const result = (metadata as Record<string, unknown>).result;

  return result === "READY" || result === "PARTIAL" || result === "ERROR"
    ? result
    : null;
}

export default async function PilotOnboardingPage({ params }: PilotPageProps) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);

  const [integration, latestProbe, latestScore] = await Promise.all([
    db.integration.findUnique({
      where: {
        organizationId_provider: {
          organizationId: membership.organization.id,
          provider: "MICROSOFT_365",
        },
      },
      select: {
        mode: true,
        status: true,
        lastSyncAt: true,
      },
    }),
    db.auditEvent.findFirst({
      where: {
        organizationId: membership.organization.id,
        action: "integration.microsoft_365.readonly_probe",
      },
      orderBy: {
        occurredAt: "desc",
      },
      select: {
        metadata: true,
        occurredAt: true,
      },
    }),
    db.securityScore.findFirst({
      where: {
        organizationId: membership.organization.id,
      },
      orderBy: {
        calculatedAt: "desc",
      },
      select: {
        calculatedAt: true,
      },
    }),
  ]);

  const scannerConfiguration = getMicrosoftGraphScannerConfiguration();
  const scannerConfigured =
    scannerConfiguration.configured && Boolean(process.env.M365_GRAPH_REDIRECT_URI);

  const readiness = buildPilotReadiness({
    scannerConfigured,
    remediationConfigured: isMicrosoftRemediationExecutorConfigured(),
    integration,
    readonlyProbeResult: getProbeResult(latestProbe?.metadata),
    hasScoreSnapshot: latestScore !== null,
  });

  return (
    <main className="shell">
      <section className="dashboard pilot-onboarding">
        <p className="eyebrow">First customer pilot</p>
        <h1 className="dashboard-title">{membership.organization.name}</h1>
        <p className="lede">
          Read-only onboarding checklist for the first real Microsoft 365
          assessment. Lab evidence never counts as customer validation.
        </p>

        <div className="pilot-status">
          <span>Assessment readiness</span>
          <strong>
            {readiness.readyForReadOnlyAssessment
              ? "READY"
              : readiness.needsAttention
                ? "NEEDS ATTENTION"
                : "NOT READY"}
          </strong>
          <p>
            The first customer pilot remains read-only. Microsoft remediation
            consent is a separate later milestone.
          </p>
        </div>

        <div className="pilot-step-list">
          {readiness.steps.map((step, index) => (
            <article className="pilot-step" key={step.id}>
              <div className="pilot-step-index">{index + 1}</div>
              <div>
                <div className="pilot-step-heading">
                  <h2>{step.title}</h2>
                  <span className="role-badge">{step.state}</span>
                </div>
                <p>{step.detail}</p>
              </div>
            </article>
          ))}
        </div>

        <div className="pilot-callout">
          <strong>Definition of done for the first pilot</strong>
          <p>
            A real tenant is connected read-only, the permission probe is
            healthy, the first evidence sync completes, findings can be
            explained against tenant evidence, and an executive report is
            generated. Write remediation stays out of scope.
          </p>
        </div>

        <div className="integration-actions">
          <Link className="secondary-button" href={`/organizations/${slug}`}>
            Back to workspace
          </Link>
          {latestScore ? (
            <Link
              className="primary-button"
              href={`/organizations/${slug}/report`}
            >
              Open executive report
            </Link>
          ) : null}
        </div>
      </section>
    </main>
  );
}
