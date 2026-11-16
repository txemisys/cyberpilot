import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../lib/organizations";
import { IntegratedActionWorkspace } from
  "../../../../components/integrated-action-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function IntegratedActionsPage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  const canWrite=["OWNER","ADMIN"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · acciones multifuente</p>
    <h1>Seguimiento de riesgos de la pyme</h1>
    <p>Asignaciones, excepciones y trazabilidad sobre
      hallazgos ya persistidos, sin automatizar intervenciones
      sobre proveedores o dispositivos de clientes.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/integrated-risks"}>Ver riesgos de origen</Link></p>
    {reviewer?<IntegratedActionWorkspace
      slug={slug} organizationId={membership.organization.id}
      canWrite={canWrite}/>:
      <p role="alert">Se requiere permiso para consultar el registro.</p>}
  </section></main>;
}
