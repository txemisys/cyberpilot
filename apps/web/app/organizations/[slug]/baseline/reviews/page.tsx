import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { BaselineTechnicalReviewWorkspace } from
  "../../../../../components/baseline-technical-review-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function BaselineReviewsPage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = membership.role === "OWNER" ||
    membership.role === "ADMIN" ||
    membership.role === "AUDITOR";
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Baseline</p>
      <h1>Revisiones técnicas y aceptación de desarrollo</h1>
      <p>Expediente por versión de diagnóstico presentado,
        con incidencias, revisor y trazabilidad.
        La revisión no equivale a una firma de cliente,
        a una certificación CIS ni a una prueba de remediación.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/baseline"}>
        Regresar al diagnóstico Baseline
      </Link></p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/baseline/actions"}>
        Consultar acciones de mejora
      </Link></p>
      <BaselineTechnicalReviewWorkspace
        slug={slug} canReview={canReview} />
    </section>
  </main>;
}
