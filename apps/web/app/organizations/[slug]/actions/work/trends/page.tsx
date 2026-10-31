import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import WorkTrendsBoard from "./work-trends-board";
type Props={params:Promise<{slug:string}>};
export default async function WorkTrendsPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Remediation operations</p>
  <h1 className="dashboard-title">Recorded work trends</h1>
  <p className="lede">{membership.organization.name} · Explore persisted
   historical coordination events without inferring control verification.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Return to operational work management</Link></p>
  <WorkTrendsBoard slug={slug}/>
 </section></main>;
}
