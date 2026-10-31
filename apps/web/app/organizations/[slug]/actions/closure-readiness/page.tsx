import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildClosureReadinessPortfolio} from "../../../../../lib/closure-readiness";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function ClosureReadinessPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams)){
  if(typeof value==="string")query.set(key,value);
 }
 const options=parseReviewListOptions(query);
 const data=await loadReviewData(membership.organization.id,{...options,limit:50,offset:0});
 const board=buildClosureReadinessPortfolio(data.findings);
 const base=`/organizations/${slug}/actions`;
 const filters=new URLSearchParams();
 if(options.search)filters.set("search",options.search);
 if(options.severity)filters.set("severity",options.severity);
 if(options.includeResolved)filters.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Review controls</p>
  <h1 className="dashboard-title">Finding closure readiness</h1>
  <p className="lede">
   Check eight independent operational requirements before discussing a security
   finding's closure. A successful checklist does not automatically close findings,
   verify remediation or certify compliance.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/decisions"}>Management decisions</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan"}>Verification work plan</Link></p>
   <p className="action-link"><Link href={base+"/dossiers"}>Evidence dossiers</Link></p>
  </div>
  <form action={base+"/closure-readiness"} method="get" className="remediation-actions">
   <label htmlFor="closure-search">Search finding</label>
   <input id="closure-search" name="search" type="search" maxLength={100}
    defaultValue={options.search??""}/>
   <label htmlFor="closure-severity">Severity</label>
   <select id="closure-severity" name="severity" defaultValue={options.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="closure-resolved">Scope</label>
   <select id="closure-resolved" name="resolved"
    defaultValue={options.includeResolved?"yes":"no"}>
    <option value="no">Open findings</option>
    <option value="yes">Include resolved findings</option>
   </select>
   <button className="secondary-button" type="submit">Assess readiness</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Findings assessed</p><strong>{board.findings}</strong></div>
   <div><p className="panel-label">Missing prerequisites</p><strong>{board.blocked}</strong></div>
   <div><p className="panel-label">Ready for human review</p><strong>{board.reviewable}</strong></div>
   <div><p className="panel-label">No missing recorded gates</p><strong>{board.fullyRecorded}</strong></div>
   <div><p className="panel-label">No observed evidence</p><strong>{board.missingObservation}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">
    This view includes the first {data.findings.length} of {data.total} matching
    findings; totals are partial. Use a narrower filter for other findings.
   </p>
  ):<p className="score-caption">All {data.total} matching findings were evaluated.</p>}
  <p className="action-link no-print">
   <a href={`/api/organizations/${slug}/actions/closure-readiness/export?${filters}`}>
    Download complete closure-readiness matrix (CSV)
   </a>
  </p>
  <section className="remediation-section">
   <h2>Review gates by finding</h2>
   {board.items.length===0?<p>No findings match the selection.</p>:(
    <ol className="remediation-list">{board.items.map(item=>(
     <li className="remediation-card" key={item.findingId}>
      <div className="remediation-heading">
       <div><p className="priority-score">{item.severity} · {item.findingStatus}</p>
        <h3>{item.title}</h3></div>
       <span className="role-badge">{item.notMet} missing gates</span>
      </div>
      <p><strong>Recorded requirements:</strong> {item.met} met,
       {item.needsReview} require human review,
       {item.notApplicable} not applicable.</p>
      <table>
       <thead><tr><th scope="col">Review requirement</th>
        <th scope="col">Recorded state</th></tr></thead>
       <tbody>{item.gates.map(gate=>(
        <tr key={gate.id}><th scope="row">{gate.label}</th>
         <td>{gate.result}</td></tr>
       ))}</tbody>
      </table>
      {item.blockedBy.length?(
       <details><summary>Missing requirements</summary>
        <ul>{item.blockedBy.map((label,index)=><li key={index}>{label}</li>)}</ul>
       </details>
      ):null}
      <p className="action-link"><Link href={base+"/closure-readiness/"+item.findingId}>
       Review all eight criteria and evidence references
      </Link></p>
      <p className="action-link"><Link href={base+"/dossiers/"+item.findingId}>
       Supporting evidence dossier
      </Link></p>
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   This is a read-only aid for authorized human review. No check marks or
   recorded values in this view update a control or change CyberScore.
  </p>
 </section></main>;
}
