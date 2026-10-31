import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildDocumentationGapPlan} from "../../../../../lib/documentation-gap-plan";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function DocumentationGapsPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const paramsInput=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams))
  if(typeof value==="string")paramsInput.set(key,value);
 const options=parseReviewListOptions(paramsInput);
 const data=await loadReviewData(membership.organization.id,{...options,limit:50,offset:0});
 const report=buildDocumentationGapPlan(data.findings);
 const base=`/organizations/${slug}/actions`;
 const exportParams=new URLSearchParams();
 if(options.search)exportParams.set("search",options.search);
 if(options.severity)exportParams.set("severity",options.severity);
 if(options.includeResolved)exportParams.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Evidence documentation</p>
  <h1 className="dashboard-title">Documentation review priorities</h1>
  <p className="lede">Identify incomplete or unreviewed records that may prevent a
   credible assessment of security improvements. These tasks concern documentation
   quality; they are not newly detected vulnerabilities.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/audit"}>Audit documentation inventory</Link></p>
   <p className="action-link"><Link href={base+"/collection"}>Evidence collection</Link></p>
   <p className="action-link"><Link href={base+"/briefing"}>Management briefing</Link></p>
  </div>
  <form action={base+"/documentation-gaps"} method="get" className="remediation-actions">
   <label htmlFor="documentation-search">Finding or rule</label>
   <input id="documentation-search" name="search" type="search" maxLength={100}
    defaultValue={options.search??""}/>
   <label htmlFor="documentation-severity">Severity</label>
   <select id="documentation-severity" name="severity" defaultValue={options.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="documentation-resolved">Finding scope</label>
   <select id="documentation-resolved" name="resolved"
    defaultValue={options.includeResolved?"yes":"no"}>
    <option value="no">Open only</option>
    <option value="yes">Include resolved</option>
   </select>
   <button type="submit" className="secondary-button">Review documentation</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Documentation questions</p><strong>{report.total}</strong></div>
   <div><p className="panel-label">Missing records</p><strong>{report.missing}</strong></div>
   <div><p className="panel-label">Require human review</p><strong>{report.requiresReview}</strong></div>
   <div><p className="panel-label">Affected findings</p><strong>{report.affectedFindings}</strong></div>
   <div><p className="panel-label">Critical finding questions</p><strong>{report.critical}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">
    Only {data.findings.length} of {data.total} matching findings are included.
    Counts are partial. Narrow filters to inspect the remaining findings.
   </p>
  ):<p className="score-caption">All {data.total} matching findings are included.</p>}
  <div className="workspace-links no-print">
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/documentation-gaps/export?${exportParams}`}>
    Export complete matching documentation review (CSV)
   </a></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/documentation-gaps/export?format=text&${exportParams}`}>
    Download reviewer instructions (text)
   </a></p>
  </div>
  <section className="remediation-section">
   <h2>Review workload by documentation category</h2>
   <table><thead><tr><th>Category</th><th>Questions</th>
    <th>Findings</th><th>Critical</th></tr></thead>
    <tbody>{report.categories.map(category=>(
     <tr key={category.name}><th>{category.name}</th>
      <td>{category.items}</td><td>{category.findings}</td>
      <td>{category.critical}</td></tr>
    ))}</tbody></table>
  </section>
  <section className="remediation-section">
   <h2>Highest-priority review requirements</h2>
   {report.items.length===0?<p>No incomplete or pending review questions appear in this selection.</p>:(
    <ol className="remediation-list">{report.items.map(item=>(
     <li className="remediation-card" key={item.id}>
      <div className="remediation-heading">
       <div><p className="priority-score">{item.severity} · {item.category}</p>
        <h3>{item.question}</h3></div>
       <span className="role-badge">{item.recordedStatus}</span>
      </div>
      <p><strong>Finding:</strong> {item.findingTitle}</p>
      <p><strong>Recorded facts:</strong> {item.explanation}</p>
      <p><strong>Why review:</strong> {item.impact}</p>
      <p><strong>Reviewer instruction:</strong> {item.requiredReviewerAction}</p>
      <p><strong>Next step:</strong> {item.nextReviewStep}</p>
      <p className="action-link"><Link href={base+"/audit/"+item.findingId}>
       Open source-linked audit packet
      </Link></p>
      <p className="action-link"><Link href={base+"/dossiers/"+item.findingId}>
       Review finding evidence dossier
      </Link></p>
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">Documentation completeness does not certify
   an effective control or establish compliance. All records are read-only.</p>
 </section></main>;
}
