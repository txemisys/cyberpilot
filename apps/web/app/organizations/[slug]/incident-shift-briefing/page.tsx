import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentShiftBriefingWorkspace } from
  "../../../../components/incident-shift-briefing-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function IncidentShiftBriefingPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canRead = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Fase 6U</p>
    <h1>Briefing de relevo del incidente</h1>
    <p>Conciliación de la actividad y los pendientes de un turno definido.
      Los roles y plazos son recomendaciones internas, no asignaciones
      persistidas ni aceptaciones reales.</p>
    <p>No se utilizan acciones de proveedor, notificaciones externas
      ni afirmaciones de contención verificada.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-operational-timeline"}>Volver al timeline</Link></p>
    {canRead ? <IncidentShiftBriefingWorkspace slug={slug} /> :
      <p role="alert">Acceso restringido a propietarios, administradores
        y auditores de esta organización.</p>}
  </section></main>;
}
