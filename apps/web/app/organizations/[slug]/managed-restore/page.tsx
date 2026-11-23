import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { ManagedRestoreWorkspace } from "../../../../components/managed-restore-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function ManagedRestorePage({params}:Props){
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const canReview=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · continuidad operativa</p>
    <h1>Objetivos RPO/RTO y restauración gestionada</h1>
    <p>Planificación y evidencia de restauración; sin operaciones sobre proveedores.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)}>Panel principal</Link></p>
    {canReview?<ManagedRestoreWorkspace slug={slug} userId={session.user.id}
      mayExport={["OWNER","ADMIN"].includes(membership.role)}/>:
      <p role="alert">Permiso de auditoría requerido.</p>}
  </section></main>;
}
