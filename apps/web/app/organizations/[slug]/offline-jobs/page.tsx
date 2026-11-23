import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { OfflineJobWorkspace } from "../../../../components/durable-offline-jobs-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function OfflineJobsPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · operaciones offline</p>
    <h1>Trabajos persistentes de inspección</h1>
    <p>Cola PostgreSQL por organización, reintentos y recuperación de leases.
      Esta consola ejecuta solo comprobaciones locales con confirmación explícita.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug)}>Volver al panel</Link></p>
    {canReview ? <OfflineJobWorkspace slug={slug}
      mayManage={["OWNER", "ADMIN"].includes(membership.role)}/> :
      <p role="alert">Permiso de revisión necesario.</p>}
  </section></main>;
}
