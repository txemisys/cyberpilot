import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {createWorkstreamPlan} from "../../../../../lib/security-workstreams";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function SecurityWorkstreamsPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams))
  if(typeof value==="string")query.set(key,value);
 const settings=parseReviewListOptions(query);
 const page=await loadReviewData(membership.organization.id,{...settings,limit:50,offset:0});
 const plan=createWorkstreamPlan(page.findings);
 const base=`/organizations/${slug}/actions`;
 const filters=new URLSearchParams();
 if(settings.search)filters.set("search",settings.search);
 if(settings.severity)filters.set("severity",settings.severity);
 if(settings.includeResolved)filters.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Operational responsibility</p>
  <h1 className="dashboard-title">Security workstreams</h1>
  <p className="lede">
   Organize current work by responsibility: collecting evidence, investigating
   findings, approving plans, executing approved changes and reviewing closure.
   These are suggested roles, not staff assignments created in CyberPilot.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/briefing"}>Management briefing</Link></p>
   <p className="action-link"><Link href={base+"/decisions"}>Decision board</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan"}>Verification plan</Link></p>
  </div>
  <form action={base+"/workstreams"} method="get" className="remediation-actions">
   <label htmlFor="stream-search">Search findings</label>
   <input id="stream-search" name="search" type="search" maxLength={100}
    defaultValue={settings.search??""} placeholder="Control or finding title"/>
   <label htmlFor="stream-severity">Severity</label>
   <select id="stream-severity" name="severity" defaultValue={settings.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="stream-resolved">Finding scope</label>
   <select id="stream-resolved" name="resolved"
    defaultValue={settings.includeResolved?"yes":"no"}>
    <option value="no">Open findings</option>
    <option value="yes">Include resolved</option>
   </select>
   <button type="submit" className="secondary-button">Update workstreams</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Work items</p><strong>{plan.total}</strong></div>
   <div><p className="panel-label">Findings reviewed</p><strong>{plan.findings}</strong></div>
   <div><p className="panel-label">Without a remediation</p><strong>{plan.unaddressedFindings}</strong></div>
   <div><p className="panel-label">No matched evidence</p><strong>{plan.noMatchedEvidence}</strong></div>
   <div><p className="panel-label">Older observations</p><strong>{plan.outdatedObservations}</strong></div>
   <div><p className="panel-label">Missing closure prerequisites</p><strong>{plan.reviewGatesMissing}</strong></div>
  </div>
  {page.total>page.findings.length?(
   <p className="permission-warning">
    Workstreams currently display only {page.findings.length} of
    {page.total} matching findings. Use the bounded full export
    for a complete selected set.
   </p>
  ):<p className="score-caption">All {page.total} selected findings are included.</p>}
  <div className="workspace-links no-print">
   <p className="action-link">
    <a href={`/api/organizations/${slug}/actions/workstreams/export?${filters}`}>
     Download complete responsibility plan (text)
    </a>
   </p>
   <p className="action-link">
    <a href={`/api/organizations/${slug}/actions/workstreams/export?format=csv&${filters}`}>
     Export complete workstream assignments proposal (CSV)
    </a>
   </p>
  </div>
  <section className="remediation-section">
   <h2>Responsible-person handoff</h2>
   <p>Export a role-by-role handoff showing the highest-priority work,
    review criteria and limitations. This does not assign a named user or
    authorize any change.</p>
   <p className="action-link no-print">
    <a href={`/api/organizations/${slug}/actions/workstreams/export?format=handoff&${filters}`}>
     Download suggested responsibility handoff (text)
    </a>
   </p>
  </section>
  <section className="remediation-section">
   <h2>Workload by responsibility</h2>
   <table>
    <thead><tr><th scope="col">Workstream</th><th scope="col">Tasks</th>
     <th scope="col">Findings</th><th scope="col">Critical</th>
     <th scope="col">High</th></tr></thead>
    <tbody>{plan.streams.map(stream=>(
     <tr key={stream.stream}>
      <th scope="row">{stream.stream}</th><td>{stream.total}</td>
      <td>{stream.affectedFindings}</td><td>{stream.critical}</td>
      <td>{stream.high}</td>
     </tr>
    ))}</tbody>
   </table>
  </section>
  {plan.streams.map((stream,index)=>(
   <section className="remediation-section" key={stream.stream}>
    <h2>{index+1}. {stream.stream} responsibility</h2>
    <p>{stream.total} proposed work items across {stream.affectedFindings} findings.</p>
    {stream.items.length===0?(
     <p>No tasks currently match this workstream.</p>
    ):(
     <ol className="remediation-list">
      {stream.items.map(item=>(
       <li key={item.id} className="remediation-card">
        <div className="remediation-heading">
         <div><p className="priority-score">{item.severity} · {item.state}</p>
          <h3>{item.title}</h3></div>
         <span className="role-badge">{item.ownerRole}</span>
        </div>
        <p><strong>Finding:</strong> {item.findingTitle}</p>
        <p><strong>Recommended work:</strong> {item.instructions}</p>
        <details>
         <summary>Completion conditions and limitations</summary>
         <h4>Review criteria</h4>
         <ol>{item.criteria.map((criterion,i)=><li key={i}>{criterion}</li>)}</ol>
         {item.limitations.length?(
          <>
           <h4>Limitations</h4>
           <ul>{item.limitations.map((warning,i)=><li key={i}>{warning}</li>)}</ul>
          </>
         ):null}
        </details>
        <p className="action-link">
         <Link href={base+"/decisions/"+item.findingId}>Open management decision agenda</Link>
        </p>
        <p className="action-link">
         <Link href={base+"/dossiers/"+item.findingId}>Open evidence dossier</Link>
        </p>
        {item.actionId?(
         <p className="action-link"><Link href={base+"/"+item.actionId}>
          Open existing remediation controls
         </Link></p>
        ):null}
       </li>
      ))}
     </ol>
    )}
   </section>
  ))}
  <p className="score-caption">
   Workstream owners are role recommendations. No users are assigned, approvals
   submitted, security changes executed, or risk scores recalculated.
  </p>
 </section></main>;
}
