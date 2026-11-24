import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentOperationalSlaWorkspace } from "../../../../components/incident-operational-sla-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function OperationalSlaPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const permitted = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Fase 6Q</p>
    <h1>Tiempos y SLA internos de respuesta</h1>
    <p>Análisis de eventos auditables, antigüedad operativa, aceptación
      de asignaciones y próximos plazos registrados.</p>
    <p>No son SLA contractuales, resultados independientes del proveedor
      ni una certificación de contención. El umbral elegido es interno.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-operational-timeline"}>Ver la línea temporal del incidente</Link></p>
    {permitted ? <IncidentOperationalSlaWorkspace slug={slug} /> :
      <p role="alert">Se requiere rol OWNER, ADMIN o AUDITOR.</p>}
  </section></main>;
}
