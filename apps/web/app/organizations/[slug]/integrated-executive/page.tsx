import Link from "next/link";
import {requireOrganizationAccess} from
  "../../../../lib/organizations";
import {IntegratedExecutiveWorkspace} from
  "../../../../components/integrated-executive-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function IntegratedExecutivePage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · informe ejecutivo offline</p>
    <h1>Estado de riesgos, cobertura y seguimiento</h1>
    <p>Registros tenant-scoped, evidencia sin clasificar como
      verificación LIVE, cobertura parcial y remediación humana
      sin atribución de certificaciones.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/integrated-actions"}>Abrir seguimiento de acciones</Link></p>
    {reviewer?<IntegratedExecutiveWorkspace
      slug={slug} organizationId={membership.organization.id}/>:
      <p role="alert">Se requiere rol de revisión del tenant.</p>}
  </section></main>;
}
