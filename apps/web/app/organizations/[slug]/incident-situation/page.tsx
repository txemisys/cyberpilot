import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentSituationWorkspace } from "../../../../components/incident-situation-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{slug:string}> };
export default async function SituationRoomPage({params}:Props) {
  const {slug} = await params;
  const {membership} = await requireOrganizationAccess(slug);
  const reviewer = ["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · centro de coordinación</p>
    <h1>Sala de situación de incidentes</h1>
    <p>Una sola revisión conservadora de caso, evidencias, activos y
      remediaciones. Las evidencias incompletas se indican expresamente.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-triage"}>Volver al triage de incidentes</Link></p>
    {reviewer&&<p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-situation-reviews"}>Abrir expedientes persistentes de revisión</Link></p>}
    {reviewer?<IncidentSituationWorkspace slug={slug}/>:
      <p role="alert">Se requiere permiso de revisión.</p>}
  </section></main>;
}
