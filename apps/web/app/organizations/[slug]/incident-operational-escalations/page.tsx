import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { IncidentOperationalEscalationsWorkspace } from "../../../../components/incident-operational-escalations-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function OperationalEscalationsPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const permitted = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  const canWrite = ["OWNER", "ADMIN"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Fase 6R</p>
    <h1>Coordinación de escalados internos</h1>
    <p>Previsualización determinista y registro voluntario de evaluaciones
      con idempotencia, leases, fencing y cola persistida PostgreSQL.</p>
    <p>Solo comprobaciones de datos locales. Los trabajos no ejecutan
      remediaciones de un proveedor ni notifican a usuarios externos.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug) +
      "/incident-assurance-handoffs"}>Volver a los handoffs</Link></p>
    {permitted ? <IncidentOperationalEscalationsWorkspace
      slug={slug} canWrite={canWrite} /> :
      <p role="alert">Se requiere rol OWNER, ADMIN o AUDITOR.</p>}
  </section></main>;
}
