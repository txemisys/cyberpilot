import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../lib/organizations";
import { MultiSourceV2Workspace } from
  "../../../../components/multisource-v2-workspace";

type Props = { params: Promise<{ slug: string }> };
export const dynamic = "force-dynamic";

export default async function MultiSourceV2Page({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canManage = membership.role === "OWNER" ||
    membership.role === "ADMIN";
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Multi-source</p>
        <h1>CyberScore v2 · Evidencia sin dependencia de M365</h1>
        <p>Motor multifuente opcional, con controles desconocidos,
          cobertura por dominio e informes independientes
          del score histórico. Esta primera pantalla ejecuta
          escenarios sintéticos y nunca afirma seguridad LIVE.</p>
        <p>
          <Link href={"/organizations/" +
            encodeURIComponent(slug)}>
            Volver a la organización
          </Link>
        </p>
        <MultiSourceV2Workspace
          slug={slug} canManage={canManage} />
      </section>
    </main>
  );
}
