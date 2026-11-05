import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { AssetInventoryWorkspace } from "../../../../components/asset-inventory-workspace";

type Context = { params: Promise<{ slug: string }> };
export default async function AssetInventoryPage({ params }: Context) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canManage = membership.role === "OWNER" || membership.role === "ADMIN";
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Assets</p>
      <h1 className="dashboard-title">Passive asset inventory</h1>
      <p className="lede">{membership.organization.name} ·
        Inventory supplied by your organization, not discovered by a scanner.</p>
      <p className="action-link">
        <Link href={`/organizations/${slug}/actions`}>Back to action center</Link>
      </p>
      <AssetInventoryWorkspace slug={slug} canManage={canManage} />
    </section>
  </main>;
}
