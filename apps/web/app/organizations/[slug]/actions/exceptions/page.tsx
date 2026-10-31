import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildReviewExceptionRegister,summarizeReviewExceptionKinds} from "../../../../../lib/review-exceptions";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function ReviewExceptionsPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const values=await searchParams;
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(values)){
  if(typeof value==="string")query.set(key,value);
 }
 const options=parseReviewListOptions(query);
 const page=await loadReviewData(membership.organization.id,{...options,limit:50,offset:0});
 const register=buildReviewExceptionRegister(page.findings);
 const categories=summarizeReviewExceptionKinds(register.items);
 const base=`/organizations/${slug}/actions`;
 const exportFilter=new URLSearchParams();
 if(options.search)exportFilter.set("search",options.search);
 if(options.severity)exportFilter.set("severity",options.severity);
 if(options.includeResolved)exportFilter.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Review consistency</p>
  <h1 className="dashboard-title">Security record exceptions</h1>
  <p className="lede">
   Identify records that deserve a second look: findings still open after
   a verified action, work newer than observed evidence, and incomplete
   approval or verification histories.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/dossiers"}>Evidence dossiers</Link></p>
   <p className="action-link"><Link href={base+"/gaps"}>Evidence gaps</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan"}>Verification plan</Link></p>
  </div>
  <form action={base+"/exceptions"} method="get" className="remediation-actions">
   <label htmlFor="exception-search">Search finding</label>
   <input id="exception-search" type="search" name="search" maxLength={100}
    defaultValue={options.search??""}/>
   <label htmlFor="exception-severity">Severity</label>
   <select id="exception-severity" name="severity" defaultValue={options.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="exception-resolved">Finding scope</label>
   <select id="exception-resolved" name="resolved"
    defaultValue={options.includeResolved?"yes":"no"}>
    <option value="no">Open findings</option>
    <option value="yes">Include resolved findings</option>
   </select>
   <button type="submit" className="secondary-button">Review records</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Review flags</p><strong>{register.count}</strong></div>
   <div><p className="panel-label">Affected findings</p><strong>{register.affectedFindings}</strong></div>
   <div><p className="panel-label">Critical flags</p><strong>{register.critical}</strong></div>
   <div><p className="panel-label">High-severity flags</p><strong>{register.high}</strong></div>
   <div><p className="panel-label">Evidence review flags</p><strong>{register.reviewEvidence}</strong></div>
   <div><p className="panel-label">Workflow review flags</p><strong>{register.needsWork}</strong></div>
  </div>
  {page.total>page.findings.length?(
   <p className="permission-warning">Only {page.findings.length} of {page.total}
    matching findings were analyzed. These counts are partial; filter further
    or export the complete matching set within the server limit.</p>
  ):<p className="score-caption">All {page.total} matching findings were analyzed.</p>}
  <p className="action-link no-print">
   <a href={`/api/organizations/${slug}/actions/exceptions/export?${exportFilter}`}>
    Export complete matching exception register (CSV)
   </a>
  </p>
  <section className="remediation-section">
   <h2>Exception types</h2>
   {categories.length===0?<p>No exception categories were detected.</p>:(
    <table>
     <thead><tr><th scope="col">Type</th><th scope="col">Flags</th>
      <th scope="col">Affected findings</th><th scope="col">Critical</th>
      <th scope="col">High</th></tr></thead>
     <tbody>{categories.map(category=>(
      <tr key={category.kind}>
       <th scope="row">{category.kind}</th>
       <td>{category.count}</td>
       <td>{category.affectedFindings}</td>
       <td>{category.critical}</td>
       <td>{category.high}</td>
      </tr>
     ))}</tbody>
    </table>
   )}
   <p className="score-caption">
    Multiple review flags can apply to the same finding. Counts are not
    additional vulnerabilities or independent proof of security failure.
   </p>
  </section>
  <section className="remediation-section">
   <h2>Items requiring review</h2>
   {register.items.length===0?(
    <div className="empty-state">
     <p>No exceptions were detected among the reviewed records.</p>
     <p>This does not mean the organization is free from security risks.</p>
    </div>
   ):(
    <ol className="remediation-list">{register.items.map(item=>(
     <li key={item.id} className="remediation-card">
      <div className="remediation-heading">
       <div><p className="priority-score">{item.severity} · {item.kind}</p>
        <h3>{item.title}</h3></div>
       <span className="role-badge">Review required</span>
      </div>
      <p><strong>Finding:</strong> {item.findingTitle}</p>
      <p>{item.explanation}</p>
      <p><strong>Suggested follow-up:</strong> {item.recommendation}</p>
      <details>
       <summary>Recorded facts behind the flag</summary>
       <ul>{item.factualContext.map((text,index)=><li key={index}>{text}</li>)}</ul>
      </details>
      <p className="action-link"><Link href={base+"/dossiers/"+item.findingId}>
       Open finding evidence dossier
      </Link></p>
      {item.remediationId?(
       <p className="action-link"><Link href={base+"/"+item.remediationId}>
        Open linked remediation
       </Link></p>
      ):null}
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   Exceptions are prompts for authorized review, not automatically confirmed
   vulnerabilities. Findings and remediation records are not modified.
  </p>
 </section></main>;
}
