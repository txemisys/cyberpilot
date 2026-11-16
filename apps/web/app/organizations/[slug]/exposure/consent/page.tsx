import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { ExposureConsentReviewWorkspace } from
  "../../../../../components/exposure-consent-review-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function ExposureConsentReviewPage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Exposure · Consentimiento</p>
      <h1>Comprobación de firmas de autorización independientes</h1>
      <p>Una firma es verificable únicamente cuando hay una clave
        institucional registrada por el operador y una revocación
        autenticada de la autoridad independiente. No se crean
        autorizaciones legales por completar este formulario.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/exposure/readiness"}>
        Volver a preparación operacional
      </Link></p>
      {canReview ?
        <ExposureConsentReviewWorkspace slug={slug} /> :
        <p role="alert">Este expediente requiere permisos
          de revisión internos.</p>}
    </section>
  </main>;
}
