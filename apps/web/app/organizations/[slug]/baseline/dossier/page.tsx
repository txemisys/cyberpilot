import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { BaselineDevelopmentDossierWorkspace } from
  "../../../../../components/baseline-development-dossier-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function BaselineDevelopmentDossierPage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canRead = membership.role === "OWNER" ||
    membership.role === "ADMIN" ||
    membership.role === "AUDITOR";
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">
        CyberPilot · Baseline · Evidencia de desarrollo
      </p>
      <h1>Expediente de conciliación técnica</h1>
      <p>Reconstruye la procedencia real de las revisiones, las acciones
        y los eventos de auditoría. No acredita seguridad certificada,
        consentimiento empresarial ni remediación aplicada.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/baseline"}>
        Regresar al diagnóstico
      </Link></p>
      {canRead ? <BaselineDevelopmentDossierWorkspace
        slug={slug}
        organizationId={membership.organization.id} /> :
        <p role="alert">La lectura de evidencias completas requiere
          permisos de revisión internos.</p>}
    </section>
  </main>;
}
