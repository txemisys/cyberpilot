import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import { ExposureDomainAuthorizationWorkspace } from
  "../../../../../components/exposure-domain-authorization-workspace";

export const dynamic = "force-dynamic";
type Props = { params: Promise<{ slug: string }> };
export default async function ExposureAuthorizationPage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canManage = membership.role === "OWNER" ||
    membership.role === "ADMIN";
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Exposure</p>
      <h1>Control de autorización de dominios</h1>
      <p>Emisión y gestión auditada de pruebas DNS/HTTPS.
        No incluye escaneo automático ni valida
        titularidad real sin un recolector autorizado.</p>
      <p><Link href={"/organizations/" +
        encodeURIComponent(slug)}>
        Volver a la organización
      </Link></p>
      <ExposureDomainAuthorizationWorkspace
        slug={slug} canManage={canManage} />
    </section>
  </main>;
}
