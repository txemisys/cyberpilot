import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../lib/organizations";
import { IntegratedRiskWorkspace } from
  "../../../../components/integrated-risk-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function IntegratedRiskPage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · sin tenants externos</p>
    <h1>Registro integrado de riesgos y evidencias</h1>
    <p>Conciliación de fuentes persistidas, con estado UNKNOWN,
      limitaciones visibles y CyberScore v2 únicamente opcional.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)}>
      Volver a la organización
    </Link></p>
    {reviewer?<IntegratedRiskWorkspace
      slug={slug} organizationId={membership.organization.id}/>:
      <p role="alert">La revisión integrada requiere rol autorizado.</p>}
  </section></main>;
}
