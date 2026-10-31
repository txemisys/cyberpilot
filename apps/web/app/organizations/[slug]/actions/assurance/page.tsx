import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildControlAssurancePortfolio} from "../../../../../lib/control-assurance";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function AssuranceOverviewPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const fields=await searchParams;
 const input=new URLSearchParams();
 for(const [key,value] of Object.entries(fields))if(typeof value==="string")input.set(key,value);
 const settings=parseReviewListOptions(input);
 const data=await loadReviewData(membership.organization.id,{...settings,limit:50,offset:0});
 const {controls,summary}=buildControlAssurancePortfolio(data.findings);
 const base=`/organizations/${slug}/actions`;
 const selection=new URLSearchParams();
 if(settings.includeResolved)selection.set("resolved","yes");
 if(settings.severity)selection.set("severity",settings.severity);
 if(settings.search)selection.set("search",settings.search);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Evidence assurance</p>
  <h1 className="dashboard-title">Security control assurance</h1>
  <p className="lede">{membership.organization.name} · Review the quality and timing of
   security evidence following remediation activity, without equating work with verified risk reduction.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>All actions</Link></p>
   <p className="action-link"><Link href={base+"/evidence"}>Evidence provenance</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan"}>Verification work plan</Link></p>
   <p className="action-link"><Link href={base+"/gaps"}>Evidence gaps</Link></p>
  </div>
  <form action={base+"/assurance"} method="get" className="remediation-actions">
   <label htmlFor="assurance-search">Find a control</label>
   <input id="assurance-search" name="search" type="search" maxLength={100}
    defaultValue={settings.search??""} placeholder="Finding title, control or description"/>
   <label htmlFor="assurance-severity">Severity</label>
   <select id="assurance-severity" name="severity" defaultValue={settings.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="assurance-resolved">Findings</label>
   <select id="assurance-resolved" name="resolved"
    defaultValue={settings.includeResolved?"yes":"no"}>
    <option value="no">Open only</option>
    <option value="yes">Include resolved</option>
   </select>
   <button className="secondary-button" type="submit">Review controls</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Controls assessed on page</p><strong>{summary.assessed}</strong></div>
   <div><p className="panel-label">Verified workflow records</p><strong>{summary.recordedVerified}</strong></div>
   <div><p className="panel-label">Observations after work</p><strong>{summary.observedAfterWork}</strong></div>
   <div><p className="panel-label">Older observations</p><strong>{summary.observedBeforeWork}</strong></div>
   <div><p className="panel-label">Declaration-only</p><strong>{summary.declarationOnly}</strong></div>
   <div><p className="panel-label">Evidence unavailable</p><strong>{summary.unavailable}</strong></div>
  </div>
  <p className="score-caption">
   Classifications count finding records, not independently proven controls.
   An observation after work must still be assessed for relevance and outcome.
  </p>
  {data.total>data.findings.length?(
   <p className="permission-warning">Showing only {data.findings.length} of {data.total}
    matching findings. Narrow filters for smaller cohorts. Portfolio counts are partial.</p>
  ):<p className="score-caption">All {data.total} matching findings are included.</p>}
  <div className="workspace-links no-print">
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/assurance/export?${selection}`}>
    Export matching control assurance (CSV)
   </a></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/assurance/export?format=text&${selection}`}>
    Download assurance review (text)
   </a></p>
  </div>
  <section className="remediation-section">
   <h2>Controls requiring review</h2>
   {controls.length===0?<p>No findings match these filters.</p>:(
    <ol className="remediation-list">{controls.map(item=>(
     <li className="remediation-card" key={item.findingId}>
      <div className="remediation-heading">
       <div><p className="priority-score">{item.severity} · {item.findingStatus}</p>
        <h3>{item.title}</h3></div>
       <span className="role-badge">{item.level}</span>
      </div>
      <p>{item.description}</p>
      <h4>{item.decisionReason}</h4>
      <p><strong>Recommended action:</strong> {item.recommendedAction}</p>
      <dl>
       <dt>Matched observed signals</dt><dd>{item.observations}</dd>
       <dt>Matched declarations</dt><dd>{item.declarations}</dd>
       <dt>Unknown or errored signals</dt><dd>{item.unknown+item.errors}</dd>
       <dt>Verified workflow records</dt><dd>{item.verifiedWorkflows}</dd>
       <dt>Last matched observation</dt>
       <dd>{item.lastObservationAt?.toISOString()??"Not recorded"}</dd>
       <dt>Last recorded work</dt>
       <dd>{item.lastWorkAt?.toISOString()??"Not recorded"}</dd>
      </dl>
      {item.limitations.length?(
       <details>
        <summary>Review limitations ({item.limitations.length})</summary>
        <ul>{item.limitations.map((text,index)=><li key={index}>{text}</li>)}</ul>
       </details>
      ):null}
      <p className="action-link"><Link href={base+"/assurance/"+item.findingId}>
       Examine this control
      </Link></p>
      <p className="action-link"><Link href={base+"/verification-plan/"+item.findingId}>
       Open verification checklist
      </Link></p>
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   Only exact control identifier matches are attributed. This page performs no scan,
   never executes an integration and never changes CyberScore or a finding's status.
  </p>
 </section></main>;
}
