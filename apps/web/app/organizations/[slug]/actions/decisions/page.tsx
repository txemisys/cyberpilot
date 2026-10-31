import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildManagementDecisionBoard} from "../../../../../lib/management-decision-board";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function ManagementDecisionBoardPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams)){
  if(typeof value==="string")query.set(key,value);
 }
 const options=parseReviewListOptions(query);
 const page=await loadReviewData(membership.organization.id,{...options,limit:50,offset:0});
 const board=buildManagementDecisionBoard(page.findings);
 const base=`/organizations/${slug}/actions`;
 const exportParams=new URLSearchParams();
 if(options.search)exportParams.set("search",options.search);
 if(options.severity)exportParams.set("severity",options.severity);
 if(options.includeResolved)exportParams.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · SME security decisions</p>
  <h1 className="dashboard-title">What needs a decision?</h1>
  <p className="lede">
   A prioritized management view combining recorded findings, work readiness,
   verification requirements and exceptions requiring review. Recommendations
   are derived from existing data and do not authorize security changes.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Security action center</Link></p>
   <p className="action-link"><Link href={base+"/queue"}>Operational queue</Link></p>
   <p className="action-link"><Link href={base+"/exceptions"}>Review exceptions</Link></p>
   <p className="action-link"><Link href={base+"/dossiers"}>Evidence dossiers</Link></p>
  </div>
  <form action={base+"/decisions"} method="get" className="remediation-actions">
   <label htmlFor="decision-search">Find security issue</label>
   <input name="search" type="search" id="decision-search" maxLength={100}
    defaultValue={options.search??""} placeholder="Control, rule or finding title"/>
   <label htmlFor="decision-severity">Severity</label>
   <select id="decision-severity" name="severity" defaultValue={options.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="decision-resolved">Finding scope</label>
   <select id="decision-resolved" name="resolved"
    defaultValue={options.includeResolved?"yes":"no"}>
    <option value="no">Open issues</option>
    <option value="yes">Include resolved issues</option>
   </select>
   <button type="submit" className="secondary-button">Rebuild decision board</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Decisions on page</p><strong>{board.summary.total}</strong></div>
   <div><p className="panel-label">Urgent</p><strong>{board.summary.urgent}</strong></div>
   <div><p className="panel-label">High priority</p><strong>{board.summary.high}</strong></div>
   <div><p className="panel-label">Require verification</p><strong>{board.summary.verification}</strong></div>
   <div><p className="panel-label">Require investigation</p><strong>{board.summary.investigation}</strong></div>
   <div><p className="panel-label">Approval decisions</p><strong>{board.summary.approval}</strong></div>
  </div>
  {page.total>page.findings.length?(
   <p className="permission-warning">
    The board includes only {page.findings.length} of {page.total} matching
    findings. Decisions outside that set are not represented.
    Narrow filters or use the bounded complete export.
   </p>
  ):<p className="score-caption">
   All {page.total} matching findings are represented in the board.
  </p>}
  <div className="workspace-links no-print">
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/decisions/export?${exportParams}`}>
    Export complete matching decisions (CSV)
   </a></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/decisions/export?format=text&${exportParams}`}>
    Download meeting agenda (text)
   </a></p>
  </div>
  <section className="remediation-section">
   <h2>Recommended decisions, ordered by priority</h2>
   {board.items.length===0?(
    <div className="empty-state">
     <p>No findings match these filters.</p>
     <p>This does not establish that security risks are absent.</p>
    </div>
   ):(
    <ol className="remediation-list">{board.items.map(item=>(
     <li className="remediation-card" key={item.id}>
      <div className="remediation-heading">
       <div>
        <p className="priority-score">{item.severity} · {item.category}</p>
        <h3>{item.title}</h3>
       </div>
       <span className="role-badge">{item.priority}</span>
      </div>
      <p><strong>Finding:</strong> {item.findingTitle}</p>
      <p>{item.reason}</p>
      <p><strong>Recommended decision:</strong> {item.recommendedAction}</p>
      <details>
       <summary>Approval conditions and verification criteria</summary>
       <h4>Prerequisites</h4>
       {item.prerequisites.length?(
        <ul>{item.prerequisites.map((x,index)=><li key={index}>{x}</li>)}</ul>
       ):<p>No prerequisites were derived.</p>}
       <h4>Verification success criteria</h4>
       <ol>{item.successCriteria.map((x,index)=><li key={index}>{x}</li>)}</ol>
       {item.warnings.length?(
        <>
         <h4>Review limitations</h4>
         <ul>{item.warnings.map((x,index)=><li key={index}>{x}</li>)}</ul>
        </>
       ):null}
      </details>
      <p className="action-link"><Link href={base+"/decisions/"+item.findingId}>Open management decision agenda</Link></p>
      <p className="action-link"><Link href={base+"/dossiers/"+item.findingId}>
       Read evidence dossier
      </Link></p>
      <p className="action-link"><Link href={base+"/verification-plan/"+item.findingId}>
       Open verification checklist
      </Link></p>
      {item.actionId?(
       <p className="action-link"><Link href={base+"/"+item.actionId}>
        Review related remediation
       </Link></p>
      ):null}
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   This board does not approve changes, execute fixes, create evidence or
   alter CyberScore. All decisions require authorization and review.
  </p>
 </section></main>;
}
