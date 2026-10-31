import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildAuditPortfolio} from "../../../../../lib/audit-preparation";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function AuditPreparationPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const input=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams))
  if(typeof value==="string")input.set(key,value);
 const settings=parseReviewListOptions(input);
 const data=await loadReviewData(membership.organization.id,{...settings,limit:50,offset:0});
 const portfolio=buildAuditPortfolio(data.findings);
 const base=`/organizations/${slug}/actions`;
 const filters=new URLSearchParams();
 if(settings.search)filters.set("search",settings.search);
 if(settings.severity)filters.set("severity",settings.severity);
 if(settings.includeResolved)filters.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Documentation readiness</p>
  <h1 className="dashboard-title">Prepare evidence for an audit</h1>
  <p className="lede">
   A traceable fifteen-question documentation inventory for security findings:
   source evidence, remediation approval, observations after work,
   verification records and remaining inconsistencies.
   This does not issue a certification or attest a passing control.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/dossiers"}>Evidence dossiers</Link></p>
   <p className="action-link"><Link href={base+"/closure-readiness"}>Closure readiness</Link></p>
   <p className="action-link"><Link href={base+"/reconciliation"}>Outcome reconciliation</Link></p>
  </div>
  <form action={base+"/audit"} method="get" className="remediation-actions">
   <label htmlFor="audit-search">Find security issue</label>
   <input id="audit-search" name="search" type="search" maxLength={100}
    defaultValue={settings.search??""} placeholder="Finding title, rule or description"/>
   <label htmlFor="audit-severity">Severity</label>
   <select id="audit-severity" name="severity" defaultValue={settings.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="audit-resolved">Findings</label>
   <select id="audit-resolved" name="resolved"
    defaultValue={settings.includeResolved?"yes":"no"}>
    <option value="no">Open findings</option>
    <option value="yes">Include resolved</option>
   </select>
   <button className="secondary-button" type="submit">Assess documentation</button>
  </form>
  <div className="panel">
   <div><p className="panel-label">Findings</p><strong>{portfolio.findings}</strong></div>
   <div><p className="panel-label">Questions assessed</p><strong>{portfolio.questions}</strong></div>
   <div><p className="panel-label">Supported facts</p><strong>{portfolio.supported}</strong></div>
   <div><p className="panel-label">Incomplete records</p><strong>{portfolio.incomplete}</strong></div>
   <div><p className="panel-label">Human review required</p><strong>{portfolio.reviewRequired}</strong></div>
   <div><p className="panel-label">Critical findings with gaps</p><strong>{portfolio.criticalWithGaps}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">
    Only {data.findings.length} of {data.total} matching findings are included;
    results are partial. Export the complete selected set within the server limit.
   </p>
  ):<p className="score-caption">
   All {data.total} matching findings are represented.
  </p>}
  <p className="action-link no-print">
   <a href={`/api/organizations/${slug}/actions/audit/export?${filters}`}>
    Download complete documentation readiness matrix (CSV)
   </a>
  </p>
  <section className="remediation-section">
   <h2>Complete review handoff</h2>
   <p>Export the audit preparation report as readable text, including
    the documentary questions, stored facts and review actions for every
    matching finding within the server limit.</p>
   <p className="action-link no-print">
    <a href={`/api/organizations/${slug}/actions/audit/export?format=text&${filters}`}>
     Download full audit preparation report (text)
    </a>
   </p>
  </section>
  <section className="remediation-section">
   <h2>Evidence packets requiring review</h2>
   {portfolio.packets.length===0?<p>No findings match the selection.</p>:(
    <ol className="remediation-list">{portfolio.packets.map(packet=>(
     <li className="remediation-card" key={packet.findingId}>
      <div className="remediation-heading">
       <div><p className="priority-score">{packet.severity} · {packet.status}</p>
        <h3>{packet.title}</h3></div>
       <span className="role-badge">{packet.incomplete} incomplete</span>
      </div>
      <p><strong>Review inventory:</strong> {packet.supported} supported,
       {packet.reviewRequired} needing human review,
       {packet.notApplicable} not applicable.</p>
      <details>
       <summary>Inspect documentation questions</summary>
       <ol>{packet.questions.map(question=>(
        <li key={question.id}>
         <p><strong>{question.category}: {question.question}</strong></p>
         <p>Recorded status: {question.status}</p>
         <p>{question.explanation}</p>
         <p><strong>Reviewer:</strong> {question.reviewInstruction}</p>
        </li>
       ))}</ol>
      </details>
      <p className="action-link"><Link href={base+"/audit/"+packet.findingId}>
       Open full audit preparation packet
      </Link></p>
      <p className="action-link"><Link href={base+"/dossiers/"+packet.findingId}>
       Review underlying evidence
      </Link></p>
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   The inventory only reports which documents or recorded states may support a
   review. It does not claim regulatory compliance or change CyberScore.
  </p>
 </section></main>;
}
