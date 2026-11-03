import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IntegrityOperationsWorkspace } from "../../../../components/integrity-operations-workspace";

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
    </>
  );
}
