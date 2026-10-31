import { db } from "@cyberpilot/database";
import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import { buildSmeRemediationOverview } from "../../../../lib/sme-remediation-overview";
import { ACTION_CENTER_VIEWS, summarizeActionCenterRecords, ACTION_CENTER_SEVERITIES } from "../../../../lib/action-center";
import { actionPageResult, actionPageUrl, parseActionPageInput } from "../../../../lib/action-pagination";
import { buildScopedActionQuery } from "../../../../lib/action-database-query";

type Params = { params: Promise<{slug:string}>; searchParams: Promise<{view?:string;status?:string;search?:string;severity?:string;page?:string;pageSize?:string;sort?:string}> };

export default async function RemediationActionCenter({params,searchParams}:Params) {
  const {slug} = await params;
  const parameters = await searchParams;
  const settings = parseActionPageInput({...parameters,status:parameters.status??parameters.view});
  const view = settings.status;
  const {membership} = await requireOrganizationAccess(slug);
  const organizationId = membership.organization.id;
  const {where,orderBy}=buildScopedActionQuery(organizationId,settings);
  const total = await db.remediation.count({where});
  const totalPages=Math.max(1,Math.ceil(total/settings.pageSize));
  const currentPage=Math.min(settings.page,totalPages);
  const remediations = await db.remediation.findMany({
    where,orderBy,
    skip:(currentPage-1)*settings.pageSize,take:settings.pageSize,
    select:{
      id:true,title:true,summary:true,status:true,mode:true,steps:true,verification:true,
      failureCode:true,createdAt:true,completedAt:true,
      finding:{select:{title:true,severity:true,status:true,lastSeenAt:true}},
    },
  });
  const pagination=actionPageResult(remediations,total,{...settings,page:currentPage});
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
  const rows=remediations.map(action=>({
    ...action,needsVerification:byId.get(action.id)?.needsVerification??false,
    findingStatus:action.finding.status,severity:action.finding.severity,
  }));
  const filtered=rows;
  const totals=summarizeActionCenterRecords(rows);
  const base=`/organizations/${slug}/actions`;
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Action center</p>
        <h1 className="dashboard-title">Security actions</h1>
        <p className="lede">{membership.organization.name} · Follow progress without confusing completed work with verified security.</p>
        <p className="action-link"><Link href={`/organizations/${slug}`}>Back to workspace</Link></p>
        <p className="action-link"><Link href={`/organizations/${slug}/actions/history`}>View recorded action history</Link></p>
        <p className="action-link"><Link href={`/organizations/${slug}/actions/workload`}>View remediation workload report</Link></p>
        <p className="action-link"><Link href={`/organizations/${slug}/actions/queue`}>See prioritized next actions</Link></p>
        <p className="action-link"><Link href={`/organizations/${slug}/actions/evidence`}>Review evidence and verification readiness</Link></p>
        <div className="panel">
          <div><p className="panel-label">Actions on this page</p><p className="panel-value">{remediations.length}</p></div>
          <div><p className="panel-label">In progress</p><p className="panel-value">{totals.inProgress}</p></div>
          <div><p className="panel-label">Needs verification</p><p className="panel-value">{totals.needsVerification}</p></div>
          <div><p className="panel-label">Verified</p><p className="panel-value">{totals.verified}</p></div>
        </div>
        <nav aria-label="Filter security actions" className="workspace-links no-print">
          {ACTION_CENTER_VIEWS.map(option=>(
            <p key={option} className="action-link">
              <Link aria-current={view===option?"page":undefined} href={actionPageUrl(base,settings,{status:option,page:1})}>
                {option==="attention"?"Needs attention":option==="active"?"In progress":option==="verified"?"Verified":"All actions"}
              </Link>
            </p>
          ))}
        </nav>
        <p className="action-link no-print"><a href={actionPageUrl(`/api/organizations/${slug}/actions/export`,settings)}>Export action overview (CSV)</a></p>
        <form method="get" action={base} className="remediation-actions">
          <input type="hidden" name="status" value={view} />
          <label htmlFor="action-search">Find an action</label>
          <input id="action-search" type="search" name="search" maxLength={120} defaultValue={settings.search} placeholder="Action title or status" />
          <label htmlFor="action-severity">Priority</label>
          <select id="action-severity" name="severity" defaultValue={settings.severity}>
            {ACTION_CENTER_SEVERITIES.map(value=><option value={value} key={value}>{value==="ALL"?"All priorities":value}</option>)}
          </select>
          <label htmlFor="action-sort">Order</label>
          <select id="action-sort" name="sort" defaultValue={settings.sort}>
            <option value="newest">Most recent first</option>
            <option value="oldest">Oldest first</option>
            <option value="severity">Highest severity first</option>
          </select>
          <label htmlFor="page-size">Per page</label>
          <select id="page-size" name="pageSize" defaultValue={settings.pageSize}>
            <option value="20">20</option><option value="50">50</option><option value="100">100</option>
          </select>
          <button type="submit" className="secondary-button">Filter actions</button>
          <Link href={actionPageUrl(base,settings,{search:"",severity:"ALL",page:1})}>Clear filters</Link>
        </form>
        <p className="score-caption">Showing {pagination.firstItem}–{pagination.lastItem} of {pagination.total} matching actions.</p>
        <nav aria-label="Action result pages" className="workspace-links no-print">
          {pagination.hasPrevious ? <p className="action-link"><Link href={actionPageUrl(base,settings,{page:pagination.page-1})}>Previous page</Link></p> : null}
          <p>Page {pagination.page} of {pagination.totalPages}</p>
          {pagination.hasNext ? <p className="action-link"><Link href={actionPageUrl(base,settings,{page:pagination.page+1})}>Next page</Link></p> : null}
        </nav>
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
                <p className="action-link"><Link href={`/organizations/${slug}/actions/${action.id}`}>Open action details</Link></p>
              </article>;
            })}
          </div>
        )}
        <p className="score-caption">Totals above describe this page of the selected filter, not the entire organization. This view uses stored remediation and progress records. It does not execute changes, refresh evidence or alter CyberScore.</p>
      </section>
    </main>
  );
}
