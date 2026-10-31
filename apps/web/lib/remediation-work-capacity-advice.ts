import type {CapacityReport,MemberLoad} from "./remediation-work-capacity";

/**
 * Identify operational load distribution anomalies without estimating
 * availability, effort, personal productivity or security improvements.
 */
export type CapacitySignal="UNASSIGNED"|"OVERDUE_CLUSTER"|"BLOCKER_CLUSTER"|
 "HANDOFF_BACKLOG"|"HIGH_ATTENTION"|"LOAD_SKEW"|"MISSING_OWNER_COVERAGE";
export type CapacityRecommendation={
 signal:CapacitySignal;affectedMemberId:string|null;
 affectedMemberName:string|null;count:number;
 severity:"HIGH"|"NORMAL";action:string;
};
export type CapacityAdvice={generatedAt:string;recommendations:CapacityRecommendation[];
 totalSignals:number;coverage:{complete:boolean;note:string};
 disclaimer:string};
export function memberCapacityRecommendations(member:MemberLoad):CapacityRecommendation[]{
 const signals:CapacityRecommendation[]=[];
 const add=(signal:CapacitySignal,count:number,severity:"HIGH"|"NORMAL",action:string)=>{
  if(count>0)signals.push({signal,affectedMemberId:member.id,
   affectedMemberName:member.name,count,severity,action});
 };
 add("OVERDUE_CLUSTER",member.overdue,member.overdue>=3?"HIGH":"NORMAL",
  "Review this owner's missed targets and record a realistic follow-up plan.");
 add("BLOCKER_CLUSTER",member.blocked,member.blocked>=2?"HIGH":"NORMAL",
  "Coordinate owners of recorded blockers and resolve dependencies.");
 add("HANDOFF_BACKLOG",member.pendingHandoffs,
  member.pendingHandoffs>=2?"HIGH":"NORMAL",
  "Request explicit handoff acceptance or decline from eligible recipients.");
 if(member.active>=10&&member.attentionPoints>=150)
  add("HIGH_ATTENTION",member.active,"HIGH",
   "Review active task distribution; record proposed reassignment before applying it.");
 return signals;
}
export function buildCapacityAdvice(report:CapacityReport):CapacityAdvice{
 const recommendations:CapacityRecommendation[]=[];
 for(const member of report.members)
  recommendations.push(...memberCapacityRecommendations(member));
 const unassigned=report.unassigned;
 if(unassigned.active>0)recommendations.push({
  signal:"UNASSIGNED",affectedMemberId:null,affectedMemberName:null,
  count:unassigned.active,severity:unassigned.active>=3?"HIGH":"NORMAL",
  action:"Review unassigned or former-member tasks and assign eligible owners.",
 });
 if(report.members.length===0&&report.summary.active>0)
  recommendations.push({
   signal:"MISSING_OWNER_COVERAGE",affectedMemberId:null,affectedMemberName:null,
   count:report.summary.active,severity:"HIGH",
   action:"Verify organization memberships before attempting work assignment.",
  });
 const {maxActive,minActive}=report.summary;
 if(report.members.length>=2&&maxActive-minActive>=5)
  recommendations.push({
   signal:"LOAD_SKEW",affectedMemberId:null,affectedMemberName:null,
   count:maxActive-minActive,severity:maxActive-minActive>=10?"HIGH":"NORMAL",
   action:"Review task counts with the team; they do not represent actual effort or availability.",
  });
 const level={HIGH:0,NORMAL:1};
 recommendations.sort((a,b)=>level[a.severity]-level[b.severity]||b.count-a.count||a.signal.localeCompare(b.signal));
 return {
  generatedAt:report.generatedAt,recommendations,totalSignals:recommendations.length,
  coverage:{complete:report.coverage.complete,
   note:"Signals use full task counts, not the truncated per-person previews."},
  disclaimer:"Recommendations require human judgement, not automatic reassignment or verification.",
 };
}
