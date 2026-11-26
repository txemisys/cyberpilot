import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentPersistedInvestigationWorkspace } from
  "../../../../components/incident-persisted-investigation-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function PersistedInvestigationPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const allowed = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · 6V</p>
    <h1>Investigaciones persistentes</h1>
    <p>Expedientes auditables con asignaciones internas,
      evidencias y revisión independiente. Sin acciones externas.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-operational-timeline"}>Volver a la línea temporal</Link></p>
    {allowed ? <IncidentPersistedInvestigationWorkspace slug={slug} /> :
      <p role="alert">Solo propietarios, administradores y auditores.</p>}
  </section></main>;
}
