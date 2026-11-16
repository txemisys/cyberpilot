import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { ExposurePassiveScheduleWorkspace } from
  "../../../../../components/exposure-passive-schedule-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function ExposureSchedulePage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canAdmin = membership.role === "OWNER" ||
    membership.role === "ADMIN";
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Exposure</p>
      <h1>Planificación y cuotas de evaluación pasiva</h1>
      <p>Configura fuentes y consulta los límites de recogida.
        Por seguridad, ninguna planificación activa escaneos ni
        obtiene autorización legal a través de esta página.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/exposure/authorization"}>
        Gestionar desafíos DNS de dominio
      </Link></p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug)}>
        Volver a organización
      </Link></p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/exposure/readiness"}>
        Revisar autorización, cuota y auditorías offline
      </Link></p>
      <ExposurePassiveScheduleWorkspace
        slug={slug} canAdmin={canAdmin} />
    </section>
  </main>;
}
