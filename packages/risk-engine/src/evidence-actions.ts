import type { EvidenceReport } from "./evidence-report";
import { auditEvidenceReport } from "./evidence-report-audit";
/** Explainable recommendations based on evidence status, not a vulnerability or CyberScore assertion. */
export type ActionPriority = "HIGH" | "MEDIUM" | "LOW";
export type EvidenceAction = {
  id: string; domain: string; controlId: string; source: string; scope: string;
  priority: ActionPriority; reason: "ERROR" | "UNKNOWN" | "DECLARED" | "MISSING_OBSERVATION";
  state: "PROPOSED"; verifiedRisk: false;
};
export function prioritizeEvidenceActions(
  report: EvidenceReport,
  organizationId: string,
  expectedControls: readonly {domain: string;controlId: string;source?: string;scope?: string}[] = [],
): EvidenceAction[] | null {
  if (!organizationId || organizationId !== report.organizationId || auditEvidenceReport(report).length) return null;
  const actions: EvidenceAction[] = [];
  const key = (domain:string, controlId:string, source:string, scope:string) => JSON.stringify([domain,controlId,source,scope]);
  for(const row of report.rows) {
    const rule = row.state === "ERROR" ? {priority:"HIGH" as const,reason:"ERROR" as const} :
      row.state === "UNKNOWN" || (row.state === "OBSERVED" && row.observedAt === null) ? {priority:"MEDIUM" as const,reason:"UNKNOWN" as const} :
      row.state === "DECLARED" ? {priority:"LOW" as const,reason:"DECLARED" as const} : null;
    if(rule) actions.push({id:key(row.domain,row.controlId,row.source,row.scope),domain:row.domain,controlId:row.controlId,source:row.source,scope:row.scope,priority:rule.priority,reason:rule.reason,state:"PROPOSED",verifiedRisk:false});
  }
  for(const item of expectedControls) {
    const observed = report.rows.some(row=>row.domain===item.domain && row.controlId===item.controlId &&
      (item.source===undefined || row.source===item.source) && (item.scope===undefined || row.scope===item.scope) &&
      row.state==="OBSERVED" && row.observedAt!==null);
    if(!observed) actions.push({id:key(item.domain,item.controlId,item.source??"",item.scope??""),domain:item.domain,controlId:item.controlId,source:item.source??"",scope:item.scope??"",priority:"MEDIUM",reason:"MISSING_OBSERVATION",state:"PROPOSED",verifiedRisk:false});
  }
  const distinct=new Map<string,EvidenceAction>();
  for(const action of actions) distinct.set(JSON.stringify([action.id,action.reason]),action);
  const rank:Record<ActionPriority,number>={HIGH:0,MEDIUM:1,LOW:2};
  return [...distinct.values()].sort((a,b)=>rank[a.priority]-rank[b.priority] || a.id.localeCompare(b.id) || a.reason.localeCompare(b.reason));
}
