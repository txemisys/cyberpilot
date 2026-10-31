import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildReconciliationPortfolio} from "../../../../../lib/remediation-reconciliation";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function ReconciliationPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams))
  if(typeof value==="string")query.set(key,value);
 const filters=parseReviewListOptions(query);
 const data=await loadReviewData(membership.organization.id,{...filters,limit:50,offset:0});
 const report=buildReconciliationPortfolio(data.findings);
 const base=`/organizations/${slug}/actions`;
 const exportQuery=new URLSearchParams();
 if(filters.search)exportQuery.set("search",filters.search);
 if(filters.severity)exportQuery.set("severity",filters.severity);
 if(filters.includeResolved)exportQuery.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Outcome consistency</p>
  <h1 className="dashboard-title">Remediation outcome reconciliation</h1>
  <p className="lede">
   Compare what happened during remediation with the current finding status
   and matched evidence dates. Identify outcomes that require explicit
   review before communicating an effective security improvement.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/exceptions"}>Record exceptions</Link></p>
   <p className="action-link"><Link href={base+"/assurance"}>Control assurance</Link></p>
   <p className="action-link"><Link href={base+"/collection"}>Evidence collection</Link></p>
  </div>
  <form action={base+"/reconciliation"} method="get" className="remediation-actions">
   <label htmlFor="reconciliation-search">Finding</label>
   <input id="reconciliation-search" name="search" type="search" maxLength={100}
    defaultValue={filters.search??""}/>
   <label htmlFor="reconciliation-severity">Severity</label>
   <select id="reconciliation-severity" name="severity" defaultValue={filters.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="reconciliation-resolved">Finding scope</label>
   <select id="reconciliation-resolved" name="resolved"
    defaultValue={filters.includeResolved?"yes":"no"}>
    <option value="no">Open findings</option>
    <option value="yes">Include resolved</option>
   </select>
   <button type="submit" className="secondary-button">Reconcile records</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Workflow assessments</p><strong>{report.total}</strong></div>
   <div><p className="panel-label">Require human review</p><strong>{report.requiresReview}</strong></div>
   <div><p className="panel-label">Verified action, open finding</p><strong>{report.verifiedOpen}</strong></div>
   <div><p className="panel-label">Work completed, unverified</p><strong>{report.completedNotVerified}</strong></div>
   <div><p className="panel-label">Failed operations</p><strong>{report.failed}</strong></div>
   <div><p className="panel-label">No action recorded</p><strong>{report.unaddressed}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">
    Only {data.findings.length} of {data.total} matching findings are included.
    Counts represent a bounded subset. Use a narrower filter for other findings.
   </p>
  ):<p className="score-caption">All {data.total} matching findings are included.</p>}
  <div className="workspace-links no-print">
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/reconciliation/export?${exportQuery}`}>
    Export full matching reconciliation (CSV)
   </a></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/reconciliation/export?format=text&${exportQuery}`}>
    Download full reconciliation briefing (text)
   </a></p>
  </div>
  <section className="remediation-section">
   <h2>Outcomes requiring review</h2>
   {report.entries.length===0?<p>No findings match the selected filters.</p>:(
    <ol className="remediation-list">{report.entries.map(item=>(
     <li className="remediation-card" key={item.id}>
      <div className="remediation-heading">
       <div><p className="priority-score">{item.severity} · {item.outcome}</p>
        <h3>{item.findingTitle}</h3></div>
       <span className="role-badge">{item.findingStatus}</span>
      </div>
      <p><strong>Remediation:</strong> {item.actionTitle??"No linked remediation"}
       {" · "}{item.actionStatus??"Not recorded"}</p>
      <p>{item.explanation}</p>
      <p><strong>Next action:</strong> {item.nextAction}</p>
      <dl>
       <dt>Most recent matched observation</dt>
       <dd>{item.lastObservationAt?.toISOString()??"Not recorded"}</dd>
       <dt>Last recorded work</dt>
       <dd>{item.lastWorkAt?.toISOString()??"Not recorded"}</dd>
       <dt>Workflow verification</dt>
       <dd>{item.verifiedAt?.toISOString()??"Not recorded"}</dd>
       <dt>Finding resolution</dt>
       <dd>{item.resolvedAt?.toISOString()??"Not recorded"}</dd>
      </dl>
      {item.warnings.length?(
       <details><summary>Limitations requiring review</summary>
        <ul>{item.warnings.map((warning,i)=><li key={i}>{warning}</li>)}</ul>
       </details>
      ):null}
      <p className="action-link"><Link href={base+"/reconciliation/"+item.findingId}>Open detailed outcome review</Link></p>
      <p className="action-link"><Link href={base+"/dossiers/"+item.findingId}>
       Inspect supporting evidence dossier
      </Link></p>
      <p className="action-link"><Link href={base+"/chronology/"+item.findingId}>
       Compare recorded event chronology
      </Link></p>
      {item.actionId?<p className="action-link">
       <Link href={base+"/"+item.actionId}>Open linked remediation</Link>
      </p>:null}
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   Consistent timestamps and states do not independently establish an effective
   security control. Reconciliation never changes the underlying finding,
   action, evidence, or CyberScore.
  </p>
 </section></main>;
}
