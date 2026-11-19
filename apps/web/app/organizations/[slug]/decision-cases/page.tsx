import Link from "next/link";
import{requireOrganizationAccess}from "../../../../lib/organizations";
import{DecisionCaseWorkspace}from "../../../../components/decision-case-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function DecisionCasesPage({params}:Props){
 const{slug}=await params;
 const{membership}=await requireOrganizationAccess(slug);
 const allowed=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
 return <main className="shell"><section className="dashboard">
 <p className="eyebrow">CyberPilot · decisión y seguimiento offline</p>
 <h1>Casos auditados derivados de evidencia</h1>
 <p>Las revisiones proceden de evidencias guardadas por organización.
 Ni una revisión declarada ni una acción enlazada acreditan remediación.</p>
 <p><Link href={"/organizations/"+encodeURIComponent(slug)+
 "/evidence-decisions"}>Revisar las decisiones de origen</Link></p>
 {allowed?<DecisionCaseWorkspace slug={slug}
 organizationId={membership.organization.id}
 canWrite={["OWNER","ADMIN"].includes(membership.role)}/>:
 <p role="alert">Rol sin permiso de revisión de casos.</p>}
 </section></main>;
}
