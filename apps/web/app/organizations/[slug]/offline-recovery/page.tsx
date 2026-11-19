import Link from "next/link";
import{requireOrganizationAccess}from "../../../../lib/organizations";
import{OfflineRecoveryWorkspace}from "../../../../components/offline-recovery-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function OfflineRecoveryPage({params}:Props){
 const{slug}=await params;
 const{membership}=await requireOrganizationAccess(slug);
 const allowed=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
 return <main className="shell"><section className="dashboard">
 <p className="eyebrow">CyberPilot · integridad offline</p>
 <h1>Ensayo de recuperación de informes persistidos</h1>
 <p>Verifica hashes, linaje, antigüedad y reproducción en memoria
 de capturas. No ejecuta una restauración SQL de producción.</p>
 <p><Link href={"/organizations/"+encodeURIComponent(slug)+
 "/offline-captures"}>Administrar capturas de origen</Link></p>
 {allowed?<OfflineRecoveryWorkspace slug={slug}
 organizationId={membership.organization.id}
 canWrite={["OWNER","ADMIN"].includes(membership.role)}/>:
 <p role="alert">Rol sin permiso de auditoría de ensayos.</p>}
 </section></main>;
}
