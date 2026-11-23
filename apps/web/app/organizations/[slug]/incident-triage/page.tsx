import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentTriageWorkspace } from "../../../../components/incident-triage-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function IncidentTriagePage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const canReview=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · operaciones de incidentes</p>
    <h1>Triage por SLA y evidencia</h1>
    <p>Priorización y análisis del historial de los casos persistidos;
      sin acciones contra proveedores.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)}>Volver al panel</Link></p>
    {canReview?<IncidentTriageWorkspace slug={slug}
      mayExport={["OWNER","ADMIN"].includes(membership.role)}/>:
      <p role="alert">Revisión de incidentes restringida.</p>}
  </section></main>;
}
