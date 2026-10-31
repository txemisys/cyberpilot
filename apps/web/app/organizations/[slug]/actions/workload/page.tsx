import {db} from "@cyberpilot/database";
import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {summarizeWorkload,buildMonthlyWorkload,workloadClosureRate} from "../../../../../lib/remediation-workload";

type Props={params:Promise<{slug:string}>};
/**
 * Organization-only operational workload report. Values are counts of persisted
 * workflows, not a cyber risk score, successful fix count or new scan.
 */
export default async function ActionWorkloadPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const [statuses,months,events]=await Promise.all([
  db.remediation.groupBy({
   by:["status"],where:{organizationId},_count:{_all:true},
  }),
  db.remediation.findMany({
   where:{organizationId},
   orderBy:[{createdAt:"desc"},{id:"asc"}],take:2000,
   select:{id:true,createdAt:true,status:true,verifiedAt:true},
  }),
  db.auditEvent.findMany({
   where:{organizationId,resourceType:"remediation"},
   orderBy:{occurredAt:"desc"},take:20,
   select:{id:true,action:true,occurredAt:true,resourceId:true},
  }),
 ]);
 const summary=summarizeWorkload(statuses.map(row=>({status:row.status,count:row._count._all})));
 const total=summary.total;
 const verified=summary.verified;
 const pending=summary.pending;
 const failed=summary.failed;
 const executing=summary.inProgress;
 const monthly=buildMonthlyWorkload(months);
 const closureRate=workloadClosureRate(summary);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Management overview</p>
  <h1 className="dashboard-title">Remediation workload</h1>
  <p className="lede">Recorded work for {membership.organization.name}. This report summarizes existing actions; it does not evaluate the strength of your security controls.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions`}>Back to action center</Link></p>
  <div className="panel">
   <div><p className="panel-label">Actions recorded</p><strong>{total}</strong></div>
   <div><p className="panel-label">Proposed or approved</p><strong>{pending}</strong></div>
   <div><p className="panel-label">Executing</p><strong>{executing}</strong></div>
   <div><p className="panel-label">Failed actions</p><strong>{failed}</strong></div>
   <div><p className="panel-label">Verified actions</p><strong>{verified}</strong></div>
   <div><p className="panel-label">Verified share of recorded actions</p><strong>{closureRate===null?"Not available":`${closureRate}%`}</strong></div>
  </div>
  <section className="remediation-section">
   <h2>Recorded workflow states</h2>
   {statuses.length===0?<p>No remediation workflow has been recorded.</p>:(
    <table><thead><tr><th scope="col">State</th><th scope="col">Actions</th></tr></thead>
     <tbody>{statuses.sort((a,b)=>b._count._all-a._count._all).map(row=>(
      <tr key={row.status}><th scope="row">{row.status}</th><td>{row._count._all}</td></tr>
     ))}</tbody>
    </table>
   )}
   <p className="score-caption">Only workflows marked VERIFIED are counted as verified. Acknowledged steps and successful executions are not equivalent to verification.</p>
  </section>
  <section className="remediation-section">
   <h2>Recent monthly activity</h2>
   {monthly.length===0?<p>No monthly activity is available.</p>:(
    <table><thead><tr><th scope="col">Month (UTC)</th><th scope="col">Created actions</th><th scope="col">Verified actions</th></tr></thead>
    <tbody>{monthly.map(({month,created,verified})=>(
     <tr key={month}><th scope="row">{month}</th><td>{created}</td><td>{verified}</td></tr>
    ))}</tbody></table>
   )}
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/workload/export`}>Export monthly summary (CSV)</a></p>
   {total>months.length?<p className="permission-warning">Monthly history uses only the latest {months.length} actions out of {total}; earlier actions are excluded. Do not treat these totals as complete.</p>:null}
  </section>
  <section className="remediation-section">
   <h2>Recent recorded events</h2>
   {events.length===0?<p>No recent workflow events recorded.</p>:(
    <ol>{events.map(event=><li key={event.id}>
     <strong>{event.action}</strong> — <time dateTime={event.occurredAt.toISOString()}>{event.occurredAt.toISOString()}</time>
    </li>)}</ol>
   )}
   <p className="action-link"><Link href={`/organizations/${slug}/actions/history`}>Full action history</Link></p>
  </section>
  <p className="score-caption">All data is tenant-scoped. This report does not modify findings, actions or CyberScore.</p>
 </section></main>;
}
