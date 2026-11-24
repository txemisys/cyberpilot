import Link from "next/link";
import {requireOrganizationAccess} from "../../../../lib/organizations";
import {IncidentTabletopWorkspace} from "../../../../components/incident-tabletop-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function IncidentTabletopPage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const permitted=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · ejercicios de seguridad</p>
    <h1>Simulador de respuesta a incidentes</h1>
    <p>Cinco playbooks, escenarios reproducibles, fallos inyectados
      y revisión de decisiones sin cambios a clientes ni proveedores.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-situation"}>Volver a la sala de situación</Link></p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-tabletop-sessions"}>Abrir seguimiento operativo persistente</Link></p>
    {permitted?<IncidentTabletopWorkspace slug={slug}/>:
      <p role="alert">Simulaciones restringidas a revisores.</p>}
  </section></main>;
}
