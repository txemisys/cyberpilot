import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildWeeklySecurityBriefing} from "../../../../../lib/security-operations-briefing";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function OperationsBriefingPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const values=await searchParams;
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(values)){
  if(typeof value==="string")query.set(key,value);
 }
 const settings=parseReviewListOptions(query);
 const data=await loadReviewData(membership.organization.id,{...settings,limit:50,offset:0});
 const report=buildWeeklySecurityBriefing(data.findings,membership.organization.name,"Selected findings");
 const base=`/organizations/${slug}/actions`;
 const exportFilters=new URLSearchParams();
 if(settings.search)exportFilters.set("search",settings.search);
 if(settings.severity)exportFilters.set("severity",settings.severity);
 if(settings.includeResolved)exportFilters.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Leadership briefing</p>
  <h1 className="dashboard-title">Security operations briefing</h1>
  <p className="lede">
   An operational meeting agenda built from security findings and actions
   already recorded for {membership.organization.name}. It brings together
   urgent review items, verification follow-up, approvals and record consistency.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/decisions"}>Management decisions</Link></p>
   <p className="action-link"><Link href={base+"/exceptions"}>Review exceptions</Link></p>
   <p className="action-link"><Link href={base+"/dossiers"}>Evidence dossiers</Link></p>
  </div>
  <form action={base+"/briefing"} method="get" className="remediation-actions">
   <label htmlFor="briefing-search">Finding or control</label>
   <input id="briefing-search" name="search" type="search" maxLength={100}
    defaultValue={settings.search??""} placeholder="Search recorded findings"/>
   <label htmlFor="briefing-severity">Severity</label>
   <select id="briefing-severity" name="severity" defaultValue={settings.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="briefing-resolved">Finding scope</label>
   <select id="briefing-resolved" name="resolved"
    defaultValue={settings.includeResolved?"yes":"no"}>
    <option value="no">Open findings only</option>
    <option value="yes">Include resolved findings</option>
   </select>
   <button type="submit" className="secondary-button">Rebuild briefing</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Findings in briefing</p><strong>{report.findings}</strong></div>
   <div><p className="panel-label">Critical open findings</p><strong>{report.criticalFindings}</strong></div>
   <div><p className="panel-label">High open findings</p><strong>{report.highFindings}</strong></div>
   <div><p className="panel-label">Verification decisions</p><strong>{report.verificationBacklog}</strong></div>
   <div><p className="panel-label">Evidence gaps</p><strong>{report.evidenceGaps}</strong></div>
   <div><p className="panel-label">Exception flags</p><strong>{report.unresolvedExceptions}</strong></div>
   <div><p className="panel-label">Approval decisions</p><strong>{report.actionsRequiringApproval}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">
    This briefing includes only {data.findings.length} of {data.total} matching
    findings. Its counts are not complete organization totals.
    Narrow filters or use the full export within the server's record limit.
   </p>
  ):<p className="score-caption">All {data.total} matching findings are included.</p>}
  <div className="workspace-links no-print">
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/briefing/export?${exportFilters}`}>
    Download complete management briefing (text)
   </a></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/briefing/export?format=csv&${exportFilters}`}>
    Export complete action agenda (CSV)
   </a></p>
  </div>
  {report.sections.map((section,index)=>(
   <section className="remediation-section" key={section.heading}>
    <h2>{index+1}. {section.heading}</h2>
    <p>{section.description}</p>
    <dl>{section.metrics.map(metric=>(
     <div key={metric.label}>
      <dt>{metric.label}</dt>
      <dd>{metric.value} — {metric.detail}</dd>
     </div>
    ))}</dl>
    <h3>Priority follow-up</h3>
    {section.tasks.length===0?<p>No tasks are currently listed in this section.</p>:(
     <ol className="remediation-list">{section.tasks.map(task=>(
      <li className="remediation-card" key={task.id}>
       <div className="remediation-heading">
        <div><p className="priority-score">{task.priority} · {task.severity}</p>
         <h4>{task.title}</h4></div>
        <span className="role-badge">{task.findingTitle}</span>
       </div>
       <p>{task.justification}</p>
       <p><strong>Suggested responsibility:</strong> {task.ownerPrompt}</p>
       <p><strong>Next step:</strong> {task.nextStep}</p>
       <details><summary>Evidence and review conditions</summary>
        <ol>{task.verificationCriteria.map((text,i)=><li key={i}>{text}</li>)}</ol>
        {task.limitations.length?(
         <ul>{task.limitations.map((text,i)=><li key={i}>{text}</li>)}</ul>
        ):null}
       </details>
       <p className="action-link"><Link href={base+"/dossiers/"+task.findingId}>
        Inspect supporting finding dossier
       </Link></p>
       {task.actionId?<p className="action-link">
        <Link href={base+"/"+task.actionId}>Review related remediation</Link>
       </p>:null}
      </li>
     ))}</ol>
    )}
   </section>
  ))}
  <section className="remediation-section">
   <h2>Important reporting limitations</h2>
   <ul>{report.caveats.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
  </section>
  <p className="score-caption">
   This briefing is not a live assessment or approval. It never modifies
   CyberScore or the status of a finding or remediation.
  </p>
 </section></main>;
}
