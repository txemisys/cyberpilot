import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { CaseActionHandoffReviewWorkspace } from "../../../../components/case-action-handoff-review-workspace";

export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function CaseActionReviewPage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · seguimiento de decisiones</p>
    <h1>Relaciones entre casos y acciones</h1>
    <p>Correlaciona hallazgos originales, decisiones conservadoras y
    acciones existentes. No crea remediación técnica ni aprueba riesgos.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/decision-cases"}>Volver al registro de casos</Link></p>
    {reviewer?<CaseActionHandoffReviewWorkspace slug={slug}
      organizationId={membership.organization.id}/>:
      <p role="alert">Se requiere permiso de revisión.</p>}
  </section></main>;
}
