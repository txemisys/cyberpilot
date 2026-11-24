import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentSituationReviewWorkspace }
  from "../../../../components/incident-situation-review-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{slug:string}> };
export default async function SituationReviewPage({params}:Props) {
  const {slug} = await params;
  const {membership} = await requireOrganizationAccess(slug);
  const reviewer = ["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  const writer = ["OWNER","ADMIN"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · continuidad operativa</p>
    <h1>Expedientes de sala de situación</h1>
    <p>Revisiones persistentes de incidentes con control de concurrencia,
      evidencias declaradas, cadena de auditoría y separación de responsabilidades.</p>
    <p>Las atestaciones internas no acreditan que una cuenta haya sido revocada,
      un dispositivo aislado o un incidente contenido por un proveedor.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-situation"}>Volver a la sala de situación</Link></p>
    {reviewer?<IncidentSituationReviewWorkspace slug={slug} canWrite={writer}/>:
      <p role="alert">Se requiere un rol de revisión autorizado.</p>}
  </section></main>;
}
