import Link from "next/link";
import {requireOrganizationAccess} from "../../../../lib/organizations";
import {OfflineSlaWorkspace} from "../../../../components/offline-sla-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function OfflineSlaPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · gestión sin tenants externos</p>
  <h1>Plazos y escalados internos de acciones</h1>
  <p>Detección de asignaciones pendientes, bloqueos, vencimientos
  y excepciones usando eventos auditados. No envía avisos, no
  modifica proveedores y no certifica remediaciones.</p>
  <p><Link href={"/organizations/"+encodeURIComponent(slug)+
    "/integrated-actions"}>Volver a seguimiento</Link></p>
  {["OWNER","ADMIN","AUDITOR"].includes(membership.role)?
   <OfflineSlaWorkspace slug={slug}
     organizationId={membership.organization.id}/>:
   <p>Revisión de plazos no autorizada para este rol.</p>}
 </section></main>;
}
