import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../lib/organizations";
import { Phase2BaselineWorkspace } from
  "../../../../components/phase2-baseline-workspace";
import { BASELINE_IG1_QUESTIONS } from "@cyberpilot/risk-engine";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function OrganizationBaselinePage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Diagnóstico para pymes</p>
      <h1>Baseline de seguridad · sin Microsoft 365</h1>
      <p>Cuestionario organizativo, recomendaciones y cobertura
        autodeclarada. Los resultados no son verificación
        técnica ni certificación CIS.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug)}>
        Volver a la organización
      </Link></p>
      <Phase2BaselineWorkspace
        slug={slug}
        organizationId={membership.organization.id}
        questions={[...BASELINE_IG1_QUESTIONS]} />
    </section>
  </main>;
}
