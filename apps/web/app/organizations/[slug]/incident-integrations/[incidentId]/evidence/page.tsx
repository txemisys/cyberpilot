import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { IncidentEvidenceIntegrationWorkspace } from "../../../../../components/incident-evidence-integration-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string; incidentId: string }> };
export default async function IncidentEvidenceIntegrationPage({ params }: Props) {
  const { slug, incidentId } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · evidencia multi-fuente</p>
    <h1>Integración de evidencias del incidente</h1>
    <p>Correlación explícita con hallazgos y decisiones existentes, sin atribución
      por coincidencias textuales ni escrituras en sistemas externos.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-triage"}>Volver al triage de incidentes</Link></p>
    {canReview ? <IncidentEvidenceIntegrationWorkspace slug={slug}
      incidentId={incidentId}/> :
      <p role="alert">Se requiere permiso de revisión de evidencia.</p>}
  </section></main>;
}
