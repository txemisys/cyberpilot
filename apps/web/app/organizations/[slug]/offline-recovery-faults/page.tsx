import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { OfflineRecoveryFaultWorkspace } from "../../../../components/offline-recovery-fault-workspace";

export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function OfflineRecoveryFaultsPage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · integridad offline</p>
    <h1>Fallos simulados sobre artefactos archivados</h1>
    <p>La matriz de fault injection opera exclusivamente en memoria.
    No modifica datos persistidos ni sustituye la restauración real
    PostgreSQL del pipeline de CI.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/offline-recovery"}>Volver a ensayos archivados</Link></p>
    {reviewer?<OfflineRecoveryFaultWorkspace slug={slug}
      organizationId={membership.organization.id}/>:
      <p role="alert">Se requiere permiso de revisión.</p>}
  </section></main>;
}
