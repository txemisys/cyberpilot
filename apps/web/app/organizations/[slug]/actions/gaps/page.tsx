import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildEvidenceGapReport} from "../../../../../lib/evidence-gap-report";

type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function EvidenceGapPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const fields=await searchParams;
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(fields)){
  if(typeof value==="string")query.set(key,value);
 }
 const options=parseReviewListOptions(query);
 const result=await loadReviewData(membership.organization.id,{
  ...options,limit:50,offset:0,
 });
 const report=buildEvidenceGapReport(result.findings);
 const base=`/organizations/${slug}/actions`;
 const exportParams=new URLSearchParams();
 if(options.includeResolved)exportParams.set("resolved","yes");
 if(options.severity)exportParams.set("severity",options.severity);
 if(options.search)exportParams.set("search",options.search);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Coverage diagnostics</p>
  <h1 className="dashboard-title">Where are evidence gaps?</h1>
  <p className="lede">Identify which findings lack matching evidence, rely on declarations,
   or have observations that predate recorded remediation work.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/evidence"}>Evidence review</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan"}>Verification plan</Link></p>
  </div>
  <form action={base+"/gaps"} method="get" className="remediation-actions">
   <label htmlFor="gaps-search">Search findings</label>
   <input id="gaps-search" type="search" name="search" maxLength={100}
    defaultValue={options.search??""}/>
   <label htmlFor="gaps-severity">Severity</label>
   <select id="gaps-severity" name="severity" defaultValue={options.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="gaps-resolved">Include resolved findings</label>
   <select name="resolved" id="gaps-resolved"
    defaultValue={options.includeResolved?"yes":"no"}>
    <option value="no">Open only</option>
    <option value="yes">Include other states</option>
   </select>
   <button type="submit" className="secondary-button">Review gaps</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Findings evaluated</p><strong>{report.summary.total}</strong></div>
   <div><p className="panel-label">No matching evidence</p><strong>{report.summary.unmatched}</strong></div>
   <div><p className="panel-label">Declaration-only</p><strong>{report.summary.declarationOnly}</strong></div>
   <div><p className="panel-label">Older than remediation</p><strong>{report.summary.observationOld}</strong></div>
   <div><p className="panel-label">Inconclusive</p><strong>{report.summary.inconclusive}</strong></div>
   <div><p className="panel-label">Unresolved after work</p><strong>{report.summary.unresolvedAfterWork}</strong></div>
  </div>
  {result.total>result.findings.length?(
   <p className="permission-warning">The diagnostics include only {result.findings.length}
    of {result.total} matching findings. Narrow the filters to see another subset.</p>
  ):<p className="score-caption">{result.total} matching findings were evaluated.</p>}
  <p className="action-link no-print">
   <a href={`/api/organizations/${slug}/actions/gaps/export?${exportParams}`}>
    Download complete matching evidence gap report (CSV)
   </a>
  </p>
  <section className="remediation-section">
   <h2>Evidence gaps requiring attention</h2>
   {report.items.length===0?<p>No findings match the requested scope.</p>:(
    <ol className="remediation-list">{report.items.map(item=>(
     <li className="remediation-card" key={item.findingId}>
      <div className="remediation-heading">
       <div>
        <p className="priority-score">{item.severity} · {item.kind}</p>
        <h3>{item.findingTitle}</h3>
       </div>
       <span className="role-badge">{item.observedCount} observed</span>
      </div>
      <p>{item.description}</p>
      <p><strong>Next step:</strong> {item.nextStep}</p>
      <dl>
       <dt>Observed records</dt><dd>{item.observedCount}</dd>
       <dt>Declared records</dt><dd>{item.declaredCount}</dd>
       <dt>Unknown / error records</dt><dd>{item.erroredCount}</dd>
       <dt>Matching observation timestamp</dt>
       <dd>{item.observationAt?.toISOString()??"Unavailable"}</dd>
       <dt>Last recorded remediation work</dt>
       <dd>{item.lastWorkAt?.toISOString()??"Not recorded"}</dd>
      </dl>
      <p className="action-link"><Link href={base+"/evidence/"+item.findingId}>
       Examine evidence provenance
      </Link></p>
      <p className="action-link"><Link href={base+"/verification-plan/"+item.findingId}>
       Verification checklist
      </Link></p>
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">Automatic attribution uses exact control identifiers.
   Unmatched data might exist under another control or scope; these classifications
   are diagnostics, not evidence that a security control is absent.</p>
 </section></main>;
}
