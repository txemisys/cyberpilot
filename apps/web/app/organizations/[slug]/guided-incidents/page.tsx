import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { GuidedIncidentWorkspace } from "../../../../components/guided-incident-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function GuidedIncidentsPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canReview = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · respuesta guiada</p>
    <h1>Respuesta a incidentes</h1>
    <p>Cinco protocolos con evidencia y control de revisiones.
      Ninguna operación técnica se ejecuta desde esta vista.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug)}>
      Volver al panel de la organización</Link></p>
    {canReview ? <GuidedIncidentWorkspace slug={slug}
      mayWrite={["OWNER", "ADMIN"].includes(membership.role)}/> :
      <p role="alert">Se requiere permiso de revisión.</p>}
  </section></main>;
}
