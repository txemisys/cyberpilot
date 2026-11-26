import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentPersistedShiftHandoffWorkspace } from
  "../../../../components/incident-persisted-shift-handoff-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function PersistedShiftHandoffPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const authorized = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · 6X</p>
    <h1>Relevos persistentes de incidentes</h1>
    <p>Entrega de turno con historial íntegro, revisión de pendientes
      y recepción independiente del operador entrante.
      La aceptación solo confirma el relevo interno.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-shift-briefing"}>Volver al briefing del turno</Link></p>
    {authorized ? <IncidentPersistedShiftHandoffWorkspace slug={slug} /> :
      <p role="alert">Solo propietarios, administradores y auditores.</p>}
  </section></main>;
}
