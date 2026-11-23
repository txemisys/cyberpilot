import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { IncidentRemediationWorkspace } from "../../../../../components/incident-remediation-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string; incidentId: string }> };
export default async function IncidentRemediationPage({ params }: Props) {
  const { slug, incidentId } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Fix con control humano</p>
    <h1>Remediación supervisada del incidente</h1>
    <p>Revisión explícita de hallazgos, remediaciones y tareas; sin ejecutar
      acciones Microsoft Graph ni convertir aprobaciones en éxito técnico.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-triage"}>Volver al triage de incidentes</Link></p>
    {canReview ? <IncidentRemediationWorkspace slug={slug}
      incidentId={incidentId}/> :
      <p role="alert">Se requiere permiso de revisión.</p>}
  </section></main>;
}
