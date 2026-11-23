import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentAssuranceHandoffWorkspace }
  from "../../../../components/incident-assurance-handoff-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function AssuranceHandoffPage({params}:Props){
  const {slug}=await params;
  const {membership,session}=await requireOrganizationAccess(slug);
  const permitted=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  const canWrite=["OWNER","ADMIN"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · seguimiento operativo</p>
    <h1>Asignaciones y escalados de aseguramiento</h1>
    <p>Seguimiento interno de controles, asignación por membresía,
      aceptación independiente, evidencias declaradas y vencimientos.</p>
    <p>No se ejecutan comandos de contención ni se envían notificaciones
      externas al gestionar este tablero.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-assurance"}>Volver al aseguramiento de incidentes</Link></p>
    {permitted?<IncidentAssuranceHandoffWorkspace slug={slug}
      userId={session.user.id} canWrite={canWrite}/>:
      <p role="alert">No dispone de permiso para consultar este tablero.</p>}
  </section></main>;
}
