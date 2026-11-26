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
    <nav aria-label="Operaciones de incidentes relacionadas">
      <p><Link href={"/organizations/" + encodeURIComponent(slug) +
        "/incident-crosscase-correlation"}>
        Correlación de incidentes seleccionados
      </Link></p>
      <p><Link href={"/organizations/" + encodeURIComponent(slug) +
        "/incident-shift-briefing"}>
        Briefing de relevo operativo
      </Link></p>
    </nav>
    <nav aria-label="Coordinación persistente">
      <p><Link href={"/organizations/" + encodeURIComponent(slug) +
        "/incident-persisted-investigations"}>Investigaciones persistentes</Link></p>
      <p><Link href={"/organizations/" + encodeURIComponent(slug) +
        "/incident-persisted-correlations"}>Correlaciones revisables</Link></p>
      <p><Link href={"/organizations/" + encodeURIComponent(slug) +
        "/incident-persisted-shift-handoffs"}>Relevos de turno auditables</Link></p>
    </nav>
    {permitted ? <IncidentOperationalTimelineWorkspace slug={slug} /> :
      <p role="alert">Acceso restringido a propietarios, administradores
        y auditores de esta organización.</p>}
  </section></main>;
}
