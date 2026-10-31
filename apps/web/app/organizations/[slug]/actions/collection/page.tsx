import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildEvidenceCollectionPlan} from "../../../../../lib/evidence-collection-planner";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function EvidenceCollectionPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams))
  if(typeof value==="string")query.set(key,value);
 const filters=parseReviewListOptions(query);
 const data=await loadReviewData(membership.organization.id,{...filters,limit:50,offset:0});
 const plan=buildEvidenceCollectionPlan(data.findings);
 const base=`/organizations/${slug}/actions`;
 const exportQuery=new URLSearchParams();
 if(filters.search)exportQuery.set("search",filters.search);
 if(filters.severity)exportQuery.set("severity",filters.severity);
 if(filters.includeResolved)exportQuery.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Evidence preparation</p>
  <h1 className="dashboard-title">Plan evidence collection</h1>
  <p className="lede">
   Prepare authorized security observations by identifying control scope,
   source limitations and evidence freshness. This plan does not perform
   scans or connect to a LIVE provider.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan"}>Verification plan</Link></p>
   <p className="action-link"><Link href={base+"/coverage"}>Source coverage</Link></p>
   <p className="action-link"><Link href={base+"/gaps"}>Evidence gap review</Link></p>
  </div>
  <form action={base+"/collection"} method="get" className="remediation-actions">
   <label htmlFor="collection-search">Find control</label>
   <input id="collection-search" name="search" type="search" maxLength={100}
    defaultValue={filters.search??""} placeholder="Finding, rule, description"/>
   <label htmlFor="collection-severity">Severity</label>
   <select id="collection-severity" name="severity" defaultValue={filters.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="collection-resolved">Finding scope</label>
   <select id="collection-resolved" name="resolved"
    defaultValue={filters.includeResolved?"yes":"no"}>
    <option value="no">Open findings only</option>
    <option value="yes">Include resolved findings</option>
   </select>
   <button type="submit" className="secondary-button">Update collection plan</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Findings reviewed</p><strong>{plan.total}</strong></div>
   <div><p className="panel-label">Refresh observations</p><strong>{plan.refreshRequired}</strong></div>
   <div><p className="panel-label">No matched evidence</p><strong>{plan.unavailable}</strong></div>
   <div><p className="panel-label">Declaration-only</p><strong>{plan.declaredOnly}</strong></div>
   <div><p className="panel-label">Inconclusive evidence</p><strong>{plan.inconclusive}</strong></div>
   <div><p className="panel-label">Observed records available</p><strong>{plan.available}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">Only {data.findings.length} of {data.total}
    matching findings are shown. This is a bounded subset and does not
    represent all organizational evidence requirements.</p>
  ):<p className="score-caption">All {data.total} matching findings are included.</p>}
  <div className="workspace-links no-print">
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/collection/export?${exportQuery}`}>
    Download complete evidence preparation guide (text)
   </a></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/collection/export?format=csv&${exportQuery}`}>
    Export evidence collection tasks (CSV)
   </a></p>
  </div>
  <section className="remediation-section">
   <h2>Collection requirements by finding</h2>
   {plan.items.length===0?<p>No findings match these filters.</p>:(
    <ol className="remediation-list">{plan.items.map(item=>(
     <li className="remediation-card" key={item.id}>
      <div className="remediation-heading">
       <div><p className="priority-score">{item.severity} · {item.state}</p>
        <h3>{item.findingTitle}</h3></div>
       <span className="role-badge">{item.needsNewObservation?"Review collection":"Review existing evidence"}</span>
      </div>
      <p>{item.headline}</p>
      <p><strong>Purpose:</strong> {item.purpose}</p>
      <dl>
       <dt>Latest matched observation</dt>
       <dd>{item.observationAt?.toISOString()??"Not recorded"}</dd>
       <dt>Latest recorded remediation</dt>
       <dd>{item.latestWorkAt?.toISOString()??"Not recorded"}</dd>
       <dt>Observed records</dt><dd>{item.observedRecordIds.length}</dd>
       <dt>Declared records</dt><dd>{item.declaredRecordIds.length}</dd>
       <dt>Inconclusive records</dt><dd>{item.inconclusiveRecordIds.length}</dd>
      </dl>
      <details>
       <summary>Collection instructions and acceptance checks</summary>
       <h4>Preparation</h4>
       <ol>{item.instructions.map((instruction,i)=><li key={i}>{instruction}</li>)}</ol>
       <h4>Independent review criteria</h4>
       <ol>{item.reviewCriteria.map((criterion,i)=><li key={i}>{criterion}</li>)}</ol>
       {item.cautions.length?(
        <>
         <h4>Current limitations</h4>
         <ul>{item.cautions.map((warning,i)=><li key={i}>{warning}</li>)}</ul>
        </>
       ):null}
      </details>
      <p className="action-link"><Link href={base+"/collection/"+item.findingId}>
       Open detailed collection checklist
      </Link></p>
      <p className="action-link"><Link href={base+"/evidence/"+item.findingId}>
       Examine evidence provenance
      </Link></p>
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   Suggested evidence collection is not proof of an effective security
   control, and does not modify findings, remediation or CyberScore.
  </p>
 </section></main>;
}
