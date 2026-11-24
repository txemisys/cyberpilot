import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentCrosscaseCorrelationWorkspace } from
  "../../../../components/incident-crosscase-correlation-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function CrosscaseCorrelationPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const permitted = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Fase 6T</p>
    <h1>Correlación supervisada entre incidentes</h1>
    <p>Compare únicamente incidentes seleccionados explícitamente.
      Los candidatos se basan en registros internos y no prueban
      una campaña, identidad de dispositivo o compromiso compartido.</p>
    <p>Las acciones de contención, borrado, revocación y bloqueo externo
      permanecen deshabilitadas.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-operational-timeline"}>
      Volver a la línea temporal
    </Link></p>
    {permitted ? <IncidentCrosscaseCorrelationWorkspace slug={slug} /> :
      <p role="alert">Acceso restringido a propietarios,
        administradores y auditores de esta organización.</p>}
  </section></main>;
}
