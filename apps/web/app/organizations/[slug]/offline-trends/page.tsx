import Link from "next/link";
import {requireOrganizationAccess} from "../../../../lib/organizations";
import {OfflineTrendWorkspace} from "../../../../components/offline-trend-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function OfflineTrendsPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
 <p className="eyebrow">CyberPilot · histórico multifuente</p>
 <h1>Comparación conservadora de evaluaciones</h1>
 <p>Historial de snapshots guardados, comparaciones entre modelos
 equivalentes y seguimiento auditable; no interpreta diferencias
 de score como seguridad LIVE.</p>
 <p><Link href={"/organizations/"+encodeURIComponent(slug)+
 "/integrated-executive"}>Volver al informe ejecutivo</Link></p>
 {["OWNER","ADMIN","AUDITOR"].includes(membership.role)?
 <OfflineTrendWorkspace slug={slug}
 organizationId={membership.organization.id}/>:
 <p>Este rol no tiene permiso para revisar comparaciones.</p>}
 </section></main>;
}
