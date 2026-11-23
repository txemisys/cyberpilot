import Link from "next/link";
import{requireOrganizationAccess}from "../../../../lib/organizations";
import{OfflineCaptureWorkspace}from "../../../../components/offline-capture-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function OfflineCapturesPage({params}:Props){
 const{slug}=await params;
 const{membership}=await requireOrganizationAccess(slug);
 const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
 return <main className="shell"><section className="dashboard">
 <p className="eyebrow">CyberPilot · archivo offline persistente</p>
 <h1>Histórico inmutable de informes y procedencia</h1>
 <p>Las capturas conservan informes del tenant con su huella local.
 No son una copia de seguridad SQL ni un certificado de seguridad.</p>
 <p><Link href={"/organizations/"+encodeURIComponent(slug)+
 "/offline-trends"}>Consultar tendencias de origen</Link></p>
 <p><Link href={"/organizations/"+encodeURIComponent(slug)+
 "/offline-capture-timeline"}>Abrir histórico de capturas persistidas</Link></p>
 {reviewer?<OfflineCaptureWorkspace slug={slug}
 organizationId={membership.organization.id}
 canWrite={["OWNER","ADMIN"].includes(membership.role)}/>:
 <p role="alert">Requiere permiso de revisión.</p>}
 </section></main>;
}
