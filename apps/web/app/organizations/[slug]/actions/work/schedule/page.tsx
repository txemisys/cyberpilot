import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {canManageWork} from "../../../../../../lib/remediation-work-input";
import WorkScheduleBoard from "./work-schedule-board";

type Props={params:Promise<{slug:string}>};
export default async function WorkSchedulePage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Remediation operations</p>
  <h1 className="dashboard-title">Work deadlines and calendar</h1>
  <p className="lede">{membership.organization.name} · Inspect task targets,
   identify missing dates and coordinate authorized rescheduling.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Back to operational coordination</Link></p>
  <WorkScheduleBoard slug={slug} canManage={canManageWork(membership.role)}/>
 </section></main>;
}
