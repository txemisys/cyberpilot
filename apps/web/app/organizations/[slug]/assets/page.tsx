import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { AssetInventoryWorkspace } from "../../../../components/asset-inventory-workspace";
import { AssetInventoryLongitudinal } from "../../../../components/asset-inventory-longitudinal";
import { AssetOsvCorrelationWorkspace } from "../../../../components/asset-osv-correlation-workspace";
import { AssetOfficialOsvWorkspace } from "../../../../components/asset-osv-official-workspace";
import { AssetOsvInspectionLedger } from "../../../../components/asset-osv-inspection-ledger";
import { AssetOsvRefreshDiagnostics } from "../../../../components/asset-osv-refresh-diagnostics";
import { AssetOsvQuotaDashboard } from "../../../../components/asset-osv-quota-dashboard";
import { AssetOsvQuotaRecovery } from "../../../../components/asset-osv-quota-recovery";
import { AssetOsvRenewalWorkspace } from "../../../../components/asset-osv-renewal-workspace";

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
      <AssetInventoryLongitudinal slug={slug} canManage={canManage} />
      <AssetOsvCorrelationWorkspace slug={slug} />
      <AssetOfficialOsvWorkspace slug={slug} canManage={canManage} />
      <AssetOsvInspectionLedger slug={slug} canManage={canManage} />
      <AssetOsvRefreshDiagnostics slug={slug} />
      <AssetOsvQuotaDashboard slug={slug} canManage={canManage} />
      <AssetOsvQuotaRecovery slug={slug} canManage={canManage} />
      <AssetOsvRenewalWorkspace slug={slug} canManage={canManage} />
    </section>
  </main>;
}
