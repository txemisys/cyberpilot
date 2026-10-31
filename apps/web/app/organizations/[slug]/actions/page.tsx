import { db } from "@cyberpilot/database";
import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { buildSmeRemediationOverview } from "../../../../lib/sme-remediation-overview";

type Params = { params: Promise<{slug:string}>; searchParams: Promise<{view?:string}> };
const VIEWS = ["attention","active","verified","all"] as const;
type View = typeof VIEWS[number];

export default async function RemediationActionCenter({params,searchParams}:Params) {
  const {slug} = await params;
  const {view:requestedView} = await searchParams;
  const view:View = VIEWS.find(value=>value===requestedView) ?? "attention";
  const {membership} = await requireOrganizationAccess(slug);
  const organizationId = membership.organization.id;

  const [remediations,total] = await Promise.all([
    db.remediation.findMany({
      where:{organizationId},
      orderBy:[{createdAt:"desc"},{id:"asc"}],
      take:200,
      select:{
        id:true,title:true,summary:true,status:true,mode:true,steps:true,verification:true,
        failureCode:true,createdAt:true,completedAt:true,
        finding:{select:{title:true,severity:true,status:true,lastSeenAt:true}},
      },
    }),
    db.remediation.count({where:{organizationId}}),
  ]);
  const stepRecords=await db.guidedRemediationStep.findMany({
    where:{organizationId,remediationId:{in:remediations.map(x=>x.id)}},
    select:{remediationId:true,stepIndex:true},
  });
  const progress=new Map<string,Set<number>>();
  for(const row of stepRecords){
    const found=progress.get(row.remediationId)??new Set<number>();
    found.add(row.stepIndex);
    progress.set(row.remediationId,found);
  }
  const overview=buildSmeRemediationOverview(remediations,progress);
  const byId=new Map(overview.items.map(item=>[item.id,item]));
  const attention=(status:string,needsVerification:boolean)=>
    needsVerification||status==="FAILED"||status==="PROPOSED"||status==="APPROVED";
  const filtered=remediations.filter(action=>{
    const summary=byId.get(action.id);
    if(view==="all")return true;
    if(view==="verified")return action.status==="VERIFIED";
    if(view==="active")return action.status==="EXECUTING";
    return attention(action.status,summary?.needsVerification??false);
  });
  const base=`/organizations/${slug}/actions`;
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Action center</p>
        <h1 className="dashboard-title">Security actions</h1>
        <p className="lede">{membership.organization.name} · Follow progress without confusing completed work with verified security.</p>
        <p className="action-link"><Link href={`/organizations/${slug}`}>Back to workspace</Link></p>
        <div className="panel">
          <div><p className="panel-label">Recent actions loaded</p><p className="panel-value">{remediations.length}</p></div>
          <div><p className="panel-label">In progress</p><p className="panel-value">{overview.inProgress}</p></div>
          <div><p className="panel-label">Needs verification</p><p className="panel-value">{overview.awaitingVerification + overview.items.filter(x=>x.needsVerification&&x.label!=="Review status").length - overview.items.filter(x=>x.needsVerification&&remediations.find(r=>r.id===x.id)?.status==="SUCCEEDED").length}</p></div>
          <div><p className="panel-label">Verified</p><p className="panel-value">{overview.verified}</p></div>
        </div>
        <nav aria-label="Filter security actions" className="workspace-links no-print">
          {VIEWS.map(option=>(
            <p key={option} className="action-link">
              <Link aria-current={view===option?"page":undefined} href={`${base}?view=${option}`}>
                {option==="attention"?"Needs attention":option==="active"?"In progress":option==="verified"?"Verified":"All actions"}
              </Link>
            </p>
          ))}
        </nav>
        {total>remediations.length?<p className="score-caption">Showing the {remediations.length} most recently created of {total} actions. Older actions are not included in these totals or filters.</p>:null}
        {filtered.length===0?(
          <div className="empty-state"><p>No actions match this view.</p></div>
        ):(
          <div className="remediation-list">
            {filtered.map(action=>{
              const summary=byId.get(action.id);
              const instructions=Array.isArray(action.steps)?action.steps.filter((x):x is string=>typeof x==="string"):[];
              const checks=Array.isArray(action.verification)?action.verification.filter((x):x is string=>typeof x==="string"):[];
              return <article className="remediation-card" key={action.id}>
                <div className="remediation-heading">
                  <div>
                    <p className="priority-score">{action.finding.severity} · {action.mode}</p>
                    <h2>{action.title}</h2>
                  </div>
                  <span className="role-badge">{summary?.label??action.status}</span>
                </div>
                <p>{action.summary}</p>
                <p className="remediation-source">Related finding: {action.finding.title} · {action.finding.status}</p>
                {summary?.percentComplete!==null&&summary?.percentComplete!==undefined?(
                  <p>{summary.completedSteps} of {summary.totalSteps} guided steps acknowledged ({summary.percentComplete}%). This does not prove the security issue is fixed.</p>
                ):null}
                {action.failureCode?<p className="auth-error">Last attempt: {action.failureCode}</p>:null}
                {summary?.needsVerification?<p className="permission-warning">Fresh evidence is required before this action can be marked verified.</p>:null}
                <details>
                  <summary>Instructions and verification criteria</summary>
                  <h3>How to address this</h3>
                  {instructions.length?<ol>{instructions.map((step,i)=><li key={i}>{step}</li>)}</ol>:<p>No guided steps supplied for this action.</p>}
                  <h3>How to verify</h3>
                  {checks.length?<ol>{checks.map((step,i)=><li key={i}>{step}</li>)}</ol>:<p>No verification checklist supplied.</p>}
                </details>
                <p className="action-link"><Link href={`/organizations/${slug}#remediation-${action.id}`}>Open action in workspace</Link></p>
              </article>;
            })}
          </div>
        )}
        <p className="score-caption">This view uses stored remediation and progress records. It does not execute changes, refresh evidence or alter CyberScore.</p>
      </section>
    </main>
  );
}
