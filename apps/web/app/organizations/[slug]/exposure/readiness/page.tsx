import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { ExposureOperationalReadinessWorkspace } from
  "../../../../../components/exposure-operational-readiness-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function ExposureReadinessPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER", "ADMIN", "AUDITOR"]
    .includes(membership.role);
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">
        CyberPilot · Exposure · Preparación operacional
      </p>
      <h1>Auditoría de autorizaciones y cuotas pasivas</h1>
      <p>Conciliación de prueba de dominio, planificaciones,
        reservas y eventos de auditoría. Este recorrido
        es exclusivamente de lectura y no permite escanear
        infraestructura externa ni acredita consentimiento legal.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/exposure/schedules"}>
        Volver a la planificación
      </Link></p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/exposure/consent"}>
        Revisar consentimiento legal firmado por autoridad independiente
      </Link></p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/exposure/ledger"}>
        Consultar registro de cuotas ejecutables y consumos
      </Link></p>
      {canReview ?
        <ExposureOperationalReadinessWorkspace
          slug={slug}
          organizationId={membership.organization.id} /> :
        <p role="alert">
          Solo las funciones de revisión interna pueden consultar
          el expediente completo de preparación operacional.
        </p>}
    </section>
  </main>;
}
