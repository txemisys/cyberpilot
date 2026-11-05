import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IntegrityOperationsWorkspace } from "../../../../components/integrity-operations-workspace";
import { IntegrityEventOperations } from "../../../../components/integrity-event-operations";
import { IntegrityOperationsReports } from "../../../../components/integrity-operations-reports";
import { IntegrityOperationalAssurance } from "../../../../components/integrity-operational-assurance";
import { IntegrityPolicyDiagnostics } from "../../../../components/integrity-policy-diagnostics";
import { IntegrityOperationsPlanning } from "../../../../components/integrity-operations-planning";
import { IntegrityInterventionConsole } from "../../../../components/integrity-intervention-console";
import { IntegrityInterventionHistory } from "../../../../components/integrity-intervention-history";
import { IntegrityPhase3CAcceptance } from "../../../../components/integrity-phase3c-acceptance";

type Props = { params: Promise<{ slug: string }> };

export default async function IntegrityOperationsPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canManage = membership.role === "OWNER" || membership.role === "ADMIN";
  return (
    <>
      <div style={{ maxWidth: 1180, margin: "0 auto", padding: "16px 24px 0" }}>
        <Link href={`/organizations/${encodeURIComponent(slug)}/actions`}>
          Back to action center
        </Link>
      </div>
      <IntegrityOperationsWorkspace slug={slug} canManage={canManage} />
      <div style={{ maxWidth: 1180, margin: "0 auto", padding: 24 }}>
        <IntegrityEventOperations slug={slug} canManage={canManage} />
        <IntegrityOperationsReports slug={slug} canManage={canManage} />
        <IntegrityOperationalAssurance slug={slug} canManage={canManage} />
        <IntegrityPolicyDiagnostics slug={slug} canManage={canManage} />
        <IntegrityOperationsPlanning slug={slug} canManage={canManage} />
        <IntegrityInterventionConsole slug={slug} canManage={canManage} />
        <IntegrityInterventionHistory slug={slug} canManage={canManage} />
        <IntegrityPhase3CAcceptance slug={slug} canManage={canManage} />
      </div>
    </>
  );
}
