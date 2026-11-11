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
import { AssetOsvScheduleWorkspace } from "../../../../components/asset-osv-schedule-workspace";
import { AssetOsvWorkerOperations } from "../../../../components/asset-osv-worker-operations";
import { AssetOsvSignedDispatchOperations } from "../../../../components/asset-osv-signed-dispatch-operations";
import { AssetOsvDispatchIncidentWorkspace } from "../../../../components/asset-osv-dispatch-incident-workspace";
import { AssetOsvKeyRotationWorkspace } from "../../../../components/asset-osv-key-rotation-workspace";
import { AssetOsvDispatchPreflightWorkspace } from "../../../../components/asset-osv-dispatch-preflight-workspace";
import { AssetOsvDispatchForensicsWorkspace } from "../../../../components/asset-osv-dispatch-forensics-workspace";
import { AssetActionGuidanceWorkspace } from "../../../../components/asset-action-guidance-workspace";
import { AssetActionCaseWorkspace } from "../../../../components/asset-action-case-workspace";
import { AssetOfflineAcceptanceWorkspace } from "../../../../components/asset-offline-acceptance-workspace";
import { AssetPrivacyReadinessWorkspace } from "../../../../components/asset-privacy-readiness-workspace";
import { AssetOfflineScenarioMatrixWorkspace } from "../../../../components/asset-offline-scenario-matrix-workspace";
import { AssetReleaseReviewWorkspace } from "../../../../components/asset-release-review-workspace";
import { AssetReleaseAuditDossierWorkspace } from "../../../../components/asset-release-audit-dossier-workspace";
import { AssetRetentionReviewWorkspace } from "../../../../components/asset-retention-review-workspace";
import { AssetOfflineCloseoutDossierWorkspace } from "../../../../components/asset-offline-closeout-dossier-workspace";
import { AssetOfflineAcceptanceRunWorkspace } from "../../../../components/asset-offline-acceptance-run-workspace";
import { AssetEvidenceIndependentReviewWorkspace } from "../../../../components/asset-evidence-independent-review-workspace";
import { AssetAcceptanceAuditReconciliationWorkspace } from "../../../../components/asset-acceptance-audit-reconciliation-workspace";

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
      <AssetOsvScheduleWorkspace slug={slug} canManage={canManage} />
      <AssetOsvWorkerOperations slug={slug} canManage={canManage} />
      <AssetOsvSignedDispatchOperations slug={slug} canManage={canManage} />
      <AssetOsvDispatchIncidentWorkspace slug={slug} canManage={canManage} />
      <AssetOsvKeyRotationWorkspace slug={slug} organizationId={membership.organization.id} canManage={canManage} />
      <AssetOsvDispatchPreflightWorkspace slug={slug} canManage={canManage} />
      <AssetOsvDispatchForensicsWorkspace slug={slug} canManage={canManage} />
      <AssetActionGuidanceWorkspace slug={slug} canManage={canManage} />
      <AssetActionCaseWorkspace slug={slug} canManage={canManage} />
      <AssetOfflineAcceptanceWorkspace slug={slug} canManage={canManage} />
      <AssetPrivacyReadinessWorkspace slug={slug} canManage={canManage} />
      <AssetOfflineScenarioMatrixWorkspace slug={slug} canManage={canManage} />
      <AssetReleaseReviewWorkspace slug={slug} canManage={canManage} />
      <AssetReleaseAuditDossierWorkspace slug={slug} canManage={canManage} />
      <AssetRetentionReviewWorkspace slug={slug} canManage={canManage} />
      <AssetOfflineCloseoutDossierWorkspace slug={slug} canManage={canManage} />
      <AssetOfflineAcceptanceRunWorkspace slug={slug} canManage={canManage} />
      <AssetEvidenceIndependentReviewWorkspace slug={slug} canManage={canManage} />
      <AssetAcceptanceAuditReconciliationWorkspace slug={slug} canManage={canManage} />
    </section>
  </main>;
}
