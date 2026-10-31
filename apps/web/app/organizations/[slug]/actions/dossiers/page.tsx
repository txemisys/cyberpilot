import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildPortfolioDossier} from "../../../../../lib/finding-dossier";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function SecurityDossierPage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const input=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams)){
  if(typeof value==="string")input.set(key,value);
 }
 const options=parseReviewListOptions(input);
 const data=await loadReviewData(membership.organization.id,{...options,limit:50,offset:0});
 const portfolio=buildPortfolioDossier(data.findings);
 const base=`/organizations/${slug}/actions`;
 const query=new URLSearchParams();
 if(options.search)query.set("search",options.search);
 if(options.severity)query.set("severity",options.severity);
 if(options.includeResolved)query.set("resolved","yes");
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Management evidence</p>
  <h1 className="dashboard-title">Security evidence dossiers</h1>
  <p className="lede">
   Review a structured evidence dossier for each security finding, combining
   remediation work, assurance, observation freshness, remaining verification
   checks, and recorded limitations.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/evidence"}>Evidence review</Link></p>
   <p className="action-link"><Link href={base+"/assurance"}>Control assurance</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan"}>Verification plan</Link></p>
  </div>
  <form method="get" action={base+"/dossiers"} className="remediation-actions">
   <label htmlFor="dossier-search">Search findings</label>
   <input id="dossier-search" name="search" type="search" maxLength={100}
    defaultValue={options.search??""} placeholder="Finding title, description or rule"/>
   <label htmlFor="dossier-severity">Severity</label>
   <select name="severity" id="dossier-severity" defaultValue={options.severity??""}>
    <option value="">All severities</option>
    <option value="CRITICAL">Critical</option>
    <option value="HIGH">High</option>
    <option value="MEDIUM">Medium</option>
    <option value="LOW">Low</option>
    <option value="INFO">Info</option>
   </select>
   <label htmlFor="dossier-state">Finding scope</label>
   <select name="resolved" id="dossier-state"
    defaultValue={options.includeResolved?"yes":"no"}>
    <option value="no">Open findings only</option>
    <option value="yes">Include resolved findings</option>
   </select>
   <button type="submit" className="secondary-button">Update dossiers</button>
   <Link href={base+"/dossiers"}>Reset</Link>
  </form>
  <div className="panel">
   <div><p className="panel-label">Findings reviewed</p><strong>{portfolio.total}</strong></div>
   <div><p className="panel-label">Open findings</p><strong>{portfolio.open}</strong></div>
   <div><p className="panel-label">With observed evidence</p><strong>{portfolio.withObserved}</strong></div>
   <div><p className="panel-label">With declarations</p><strong>{portfolio.withDeclared}</strong></div>
   <div><p className="panel-label">With verified workflows</p><strong>{portfolio.withVerifiedRemediation}</strong></div>
   <div><p className="panel-label">Awaiting evidence review</p><strong>{portfolio.awaitingEvidence}</strong></div>
   <div><p className="panel-label">No matched evidence</p><strong>{portfolio.withoutMatchedEvidence}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">
    Only {data.findings.length} of {data.total} matching findings are shown.
    This portfolio is partial. Narrow filters for a focused review or use the
    full export subject to its explicit record limit.
   </p>
  ):(
   <p className="score-caption">
    This portfolio includes all {data.total} findings matching the filters.
   </p>
  )}
  <div className="workspace-links no-print">
   <p className="action-link">
    <a href={`/api/organizations/${slug}/actions/dossiers/export?${query}`}>
     Download complete filtered evidence dossier
    </a>
   </p>
  </div>
  <section className="remediation-section">
   <h2>Findings and review summaries</h2>
   {portfolio.findings.length===0?(
    <div className="empty-state">
     <p>There are no findings matching the selected scope.</p>
    </div>
   ):(
    <ol className="remediation-list">
     {portfolio.findings.map(dossier=>(
      <li key={dossier.findingId} className="remediation-card">
       <div className="remediation-heading">
        <div>
         <p className="priority-score">{dossier.severity} · {dossier.findingStatus}</p>
         <h3>{dossier.title}</h3>
        </div>
        <span className="role-badge">{dossier.assurance}</span>
       </div>
       <p><strong>Evidence review:</strong> {dossier.assessment}</p>
       <p><strong>Evidence gap:</strong> {dossier.gap}</p>
       <p><strong>Next step:</strong> {dossier.nextAction}</p>
       <dl>
        <dt>Observed signals</dt><dd>{dossier.observed}</dd>
        <dt>Declared signals</dt><dd>{dossier.declared}</dd>
        <dt>Unknown or error signals</dt><dd>{dossier.unknown+dossier.errors}</dd>
        <dt>Remediation workflows</dt><dd>{dossier.remediations}</dd>
        <dt>Verified remediation workflows</dt><dd>{dossier.verifiedRemediations}</dd>
        <dt>Latest observation</dt>
        <dd>{dossier.latestEvidenceAt?.toISOString()??"Not recorded"}</dd>
       </dl>
       {dossier.warnings.length?(
        <details>
         <summary>Review limitations ({dossier.warnings.length})</summary>
         <ul>{dossier.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
        </details>
       ):null}
       <p className="action-link">
        <Link href={base+"/dossiers/"+dossier.findingId}>Open full evidence dossier</Link>
       </p>
       <p className="action-link">
        <Link href={base+"/verification-plan/"+dossier.findingId}>
         Open verification checklist
        </Link>
       </p>
      </li>
     ))}
    </ol>
   )}
  </section>
  <p className="score-caption">
   Dossiers summarize stored data; no LIVE provider scans are performed.
   A finding being listed as resolved, or a remediation being verified, must
   be interpreted alongside its evidence and scope. CyberScore is unchanged.
  </p>
 </section></main>;
}
