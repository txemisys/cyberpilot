import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { OfflineCaptureTimelineWorkspace } from "../../../../components/offline-capture-timeline-workspace";

export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};

export default async function OfflineCaptureTimelinePage({params}:Props) {
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · histórico persistido offline</p>
    <h1>Serie de capturas y evolución de procedencia</h1>
    <p>Comparación de informes archivados en PostgreSQL,
    con controles de integridad y versiones. No ejecuta escaneos,
    restauraciones SQL ni acciones de remediación.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/offline-captures"}>Volver al archivo inmutable</Link></p>
    {reviewer?<OfflineCaptureTimelineWorkspace slug={slug}
      organizationId={membership.organization.id}/>:
      <p role="alert">Se requiere acceso de revisión.</p>}
  </section></main>;
}
