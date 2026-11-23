import Link from "next/link";
import {requireOrganizationAccess} from "../../../../lib/organizations";
import {IncidentAssuranceWorkspace} from "../../../../components/incident-assurance-workspace";
export const dynamic="force-dynamic";
type Props={params:Promise<{slug:string}>};
export default async function IncidentAssurancePage({params}:Props){
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const reviewer=["OWNER","ADMIN","AUDITOR"].includes(membership.role);
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · controles de respuesta</p>
    <h1>Preparación y aseguramiento de incidentes</h1>
    <p>Controles verificables sobre los registros offline,
      dudas de cobertura y autorizaciones segregadas.
      El dossier no acredita contención técnica ni consentimiento LIVE.</p>
    <p><Link href={"/organizations/"+encodeURIComponent(slug)+
      "/incident-situation"}>Volver a la sala de situación</Link></p>
    {reviewer?<IncidentAssuranceWorkspace slug={slug}/>:
      <p role="alert">Se requieren permisos de revisión.</p>}
  </section></main>;
}
