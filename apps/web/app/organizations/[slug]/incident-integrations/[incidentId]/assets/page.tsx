import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { IncidentAssetsWorkspace } from "../../../../../../components/incident-assets-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string; incidentId: string }> };
export default async function IncidentAssetsPage({ params }: Props) {
  const { slug, incidentId } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · inventario y exposición</p>
    <h1>Impacto del incidente sobre activos</h1>
    <p>Inventarios importados y cobertura OSV, sin inferencias de identidad
      ni órdenes de aislamiento o borrado remoto.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-triage"}>Volver al triage</Link></p>
    {canReview ? <IncidentAssetsWorkspace slug={slug} incidentId={incidentId}/> :
      <p role="alert">Permiso de revisión de activos requerido.</p>}
  </section></main>;
}
