import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { BaselineFollowUpsWorkspace } from
  "../../../../../components/baseline-followups-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function BaselineActionsPage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canEdit = membership.role !== "AUDITOR";
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Baseline</p>
      <h1>Seguimiento de acciones de mejora</h1>
      <p>Acciones declaradas, asignaciones y trazabilidad
        por revisión. Una tarea completada no implica que
        su control haya sido verificado.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug) + "/baseline"}>
        Volver al diagnóstico
      </Link></p>
      <BaselineFollowUpsWorkspace slug={slug} canEdit={canEdit} />
    </section>
  </main>;
}
