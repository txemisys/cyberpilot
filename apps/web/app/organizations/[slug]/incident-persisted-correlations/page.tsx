import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentPersistedCorrelationWorkspace } from
  "../../../../components/incident-persisted-correlation-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function PersistedCorrelationsPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const permitted = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · 6W</p>
    <h1>Hipótesis de correlación persistentes</h1>
    <p>Tableros de revisión auditables para incidentes seleccionados.
      El soporte interno no prueba identidades compartidas ni campañas.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-crosscase-correlation"}>Volver a la correlación exploratoria</Link></p>
    {permitted ? <IncidentPersistedCorrelationWorkspace slug={slug} /> :
      <p role="alert">Solo propietarios, administradores y auditores.</p>}
  </section></main>;
}
