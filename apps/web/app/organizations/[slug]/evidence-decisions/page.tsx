import Link from "next/link";
import {requireOrganizationAccess} from "../../../../lib/organizations";
import {EvidenceDecisionWorkspace} from "../../../../components/evidence-decision-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function EvidenceDecisionPage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · calidad de evidencia</p>
    <h1>Cola de revisión y procedencia de fuentes</h1>
    <p>Decisiones conservadoras desde PostgreSQL sin requerir conexión
    a un tenant externo. El estado desconocido permanece desconocido.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/integrated-risks"}>Volver a riesgos integrados</Link></p>
    {["OWNER","ADMIN","AUDITOR"].includes(membership.role)?
      <EvidenceDecisionWorkspace slug={slug}
        organizationId={membership.organization.id}/>:
      <p>Se requiere autorización de lectura y revisión.</p>}
  </section></main>;
}
