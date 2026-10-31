import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildVerificationPlan} from "../../../../../lib/verification-plan";

type Props={
 params:Promise<{slug:string}>;
 searchParams:Promise<Record<string,string|undefined>>;
};
export default async function VerificationPlanPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const request=await searchParams;
 const query=new URLSearchParams();
 for(const [key,value] of Object.entries(request)){
  if(typeof value==="string")query.set(key,value);
 }
 const options=parseReviewListOptions(query);
 // The planning view is deliberately bounded. A larger organization should
 // filter the set, not mistake a truncated export for a complete report.
 const result=await loadReviewData(membership.organization.id,{
  ...options,limit:50,offset:0,
 });
 const plan=buildVerificationPlan(result.findings);
 const base=`/organizations/${slug}/actions`;
 const exportParams=new URLSearchParams();
 if(options.includeResolved)exportParams.set("resolved","yes");
 if(options.severity)exportParams.set("severity",options.severity);
 if(options.search)exportParams.set("search",options.search);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Evidence-based operations</p>
  <h1 className="dashboard-title">Verification work plan</h1>
  <p className="lede">
   Understand what remains to be approved, performed, investigated and verified.
   These are proposed operational tasks derived from stored findings, not new security observations.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>All actions</Link></p>
   <p className="action-link"><Link href={base+"/evidence"}>Evidence review</Link></p>
   <p className="action-link"><Link href={base+"/queue"}>Operational queue</Link></p>
  </div>
  <form method="get" action={base+"/verification-plan"} className="remediation-actions">
   <label htmlFor="plan-search">Search findings</label>
   <input id="plan-search" type="search" name="search" maxLength={100}
    defaultValue={options.search??""} placeholder="Control, title, or description"/>
   <label htmlFor="plan-severity">Severity</label>
   <select id="plan-severity" name="severity" defaultValue={options.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="plan-resolved">Finding scope</label>
   <select id="plan-resolved" name="resolved"
    defaultValue={options.includeResolved?"yes":"no"}>
    <option value="no">Open only</option>
    <option value="yes">Include resolved</option>
   </select>
   <button type="submit" className="secondary-button">Update work plan</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Tasks generated</p><strong>{plan.total}</strong></div>
   <div><p className="panel-label">Awaiting approval</p><strong>{plan.pendingApproval}</strong></div>
   <div><p className="panel-label">Perform work</p><strong>{plan.performWork}</strong></div>
   <div><p className="panel-label">Collect or inspect evidence</p><strong>{plan.collectEvidence}</strong></div>
   <div><p className="panel-label">Investigate</p><strong>{plan.investigate}</strong></div>
   <div><p className="panel-label">Review closure</p><strong>{plan.reviewClosure}</strong></div>
  </div>
  {result.total>result.findings.length?(
   <p className="permission-warning">
    This plan covers only the first {result.findings.length} of {result.total} matching
    findings. Narrow filters to review another subset. This is not a complete organization report.
   </p>
  ):<p className="score-caption">All {result.total} matching findings are included.</p>}
  <p className="action-link no-print">
   <a href={base.replace("/organizations/","/api/organizations/")+"/verification-plan/export?"+exportParams.toString()}>
    Download complete filtered plan (text)
   </a>
  </p>
  <section className="remediation-section">
   <h2>Highest-priority next action</h2>
   {plan.highestPriority?(
    <article className="remediation-card">
     <p className="priority-score">{plan.highestPriority.severity}</p>
     <h3>{plan.highestPriority.title}</h3>
     <p>{plan.highestPriority.findingTitle}</p>
     <p>{plan.highestPriority.suggestedNextStep}</p>
     <p className="action-link"><Link href={base+"/verification-plan/"+plan.highestPriority.findingId}>
      Open finding verification checklist
     </Link></p>
    </article>
   ):<p>No outstanding tasks are present in the loaded findings.</p>}
  </section>
  <section className="remediation-section">
   <h2>Prioritized verification tasks</h2>
   {plan.items.length===0?(
    <div className="empty-state"><p>No findings match the selected scope.</p></div>
   ):<ol className="remediation-list">{plan.items.map(task=>(
    <li className="remediation-card" key={task.id}>
     <div className="remediation-heading">
      <div>
       <p className="priority-score">{task.severity} · {task.status}</p>
       <h3>{task.title}</h3>
      </div>
      <span className="role-badge">{task.actionTitle??"No assigned action"}</span>
     </div>
     <p><strong>Finding:</strong> {task.findingTitle}</p>
     <p>{task.description}</p>
     <p><strong>Next step:</strong> {task.suggestedNextStep}</p>
     <details>
      <summary>Success criteria and prerequisites</summary>
      <h4>Criteria</h4>
      <ol>{task.successCriteria.map((step,index)=><li key={index}>{step}</li>)}</ol>
      {task.prerequisites.length?<>
       <h4>Before starting</h4>
       <ul>{task.prerequisites.map((step,index)=><li key={index}>{step}</li>)}</ul>
      </>:null}
      {task.warnings.length?<>
       <h4>Important limitations</h4>
       <ul>{task.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
      </>:null}
     </details>
     <p className="action-link"><Link href={base+"/verification-plan/"+task.findingId}>
      View verification checklist
     </Link></p>
     {task.actionId?<p className="action-link"><Link href={base+"/"+task.actionId}>
      Open remediation
     </Link></p>:null}
    </li>
   ))}</ol>}
  </section>
  <p className="score-caption">
   This read-only plan never approves actions, executes changes, records attestations
   or modifies CyberScore. Verification must come from appropriately sourced evidence.
  </p>
 </section></main>;
}
