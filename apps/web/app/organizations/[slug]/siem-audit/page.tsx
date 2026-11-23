import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { SiemAuditWorkspace } from "../../../../components/siem-audit-workspace";
export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function SiemAuditPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canRead = ["OWNER", "ADMIN", "AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · evidencia operativa</p>
    <h1>Exportación de auditoría SIEM</h1>
    <p>Registros internos existentes, protección de datos, cursor autenticado
      y exportación revisable. No se ejecuta transporte externo.</p>
    <p><Link href={"/organizations/" + encodeURIComponent(slug)}>Volver al panel</Link></p>
    {canRead ? <SiemAuditWorkspace slug={slug}
      mayExport={["OWNER", "ADMIN"].includes(membership.role)}/> :
      <p role="alert">Permiso de auditoría necesario.</p>}
  </section></main>;
}
