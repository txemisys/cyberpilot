import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentTabletopSessionWorkspace }
  from "../../../../components/incident-tabletop-session-workspace";
export const dynamic = "force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function TabletopSessionsPage({params}:Props){
  const {slug}=await params;
  const {membership,session}=await requireOrganizationAccess(slug);
  const permitted=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  const canWrite=["OWNER","ADMIN"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · preparación operativa</p>
    <h1>Sesiones tabletop auditables</h1>
    <p>Entrenamiento reproducible para los cinco flujos de incidentes,
      con participantes, permisos, versiones, decisiones y replay persistido.</p>
    <p>La simulación no ejecuta acciones en Microsoft 365,
      Google Workspace, dispositivos ni sistemas de terceros.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-tabletop"}>Volver al simulador</Link></p>
    {permitted?<IncidentTabletopSessionWorkspace slug={slug}
      userId={session.user.id} canWrite={canWrite}/>:
      <p role="alert">Se requiere permiso de revisión.</p>}
  </section></main>;
}
