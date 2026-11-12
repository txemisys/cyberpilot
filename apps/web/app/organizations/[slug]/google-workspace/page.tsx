import Link from "next/link";
import { requireOrganizationAccess } from
  "../../../../lib/organizations";
import { GoogleWorkspaceLabWorkspace } from
  "../../../../components/google-workspace-lab-workspace";

type Props = { params: Promise<{ slug: string }> };
export const dynamic = "force-dynamic";
export default async function GoogleWorkspaceLabPage({
  params,
}: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const canManage = membership.role === "OWNER" ||
    membership.role === "ADMIN";
  return (
    <div style={{ padding: "24px 16px", maxWidth: 1240,
      margin: "0 auto" }}>
      <nav aria-label="Navegación de organización">
        <Link href={"/organizations/" + encodeURIComponent(slug)}>
          Volver a la organización
        </Link>
      </nav>
      <h1>Google Workspace · Desarrollo offline</h1>
      <p>Conector simulado de segundo proveedor de identidad.
        Directory, Reports y verificaciones locales sin credenciales
        Google ni servicios externos.</p>
      <GoogleWorkspaceLabWorkspace slug={slug}
        canManage={canManage} />
    </div>
  );
}
