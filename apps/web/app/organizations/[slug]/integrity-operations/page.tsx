import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IntegrityOperationsWorkspace } from "../../../../components/integrity-operations-workspace";
import { IntegrityEventOperations } from "../../../../components/integrity-event-operations";
import { IntegrityOperationsReports } from "../../../../components/integrity-operations-reports";

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
      </div>
    </>
  );
}
