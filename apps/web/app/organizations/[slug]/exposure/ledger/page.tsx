import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { ExposureExecutionLedgerWorkspace } from
  "../../../../../components/exposure-execution-ledger-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function ExposureExecutionLedgerPage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Exposure · Quota ledger</p>
      <h1>Registro de leases y consumos atómicos</h1>
      <p>Consistencia de reservas PostgreSQL de ejecución, identidad
        de cada operación y motivos de denegación. El registro
        de ejecución es distinto de la planificación hipotética
        de cuotas de Exposure.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/exposure/readiness"}>
        Volver a preparación offline
      </Link></p>
      {canReview ?
        <ExposureExecutionLedgerWorkspace
          slug={slug} organizationId={membership.organization.id} /> :
        <p role="alert">Esta auditoría requiere una función
          autorizada de revisión interna.</p>}
    </section>
  </main>;
}
