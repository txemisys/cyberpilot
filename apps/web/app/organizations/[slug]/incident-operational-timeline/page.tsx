import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentOperationalTimelineWorkspace } from "../../../../components/incident-operational-timeline-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function IncidentTimelinePage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const permitted = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Fase 6P</p>
    <h1>Línea temporal operativa del incidente</h1>
    <p>Proyección de eventos persistidos del caso, revisiones de situación,
      sesiones tabletop y tableros de aseguramiento.</p>
    <p>Los registros internos no constituyen prueba de ejecución ni
      verificación de acciones de un proveedor externo. El estado de
      integridad indica los límites de la reconstrucción.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-situation"}>Volver a la situación operativa</Link></p>
    {permitted ? <IncidentOperationalTimelineWorkspace slug={slug} /> :
      <p role="alert">Acceso restringido a propietarios, administradores
        y auditores de esta organización.</p>}
  </section></main>;
}
