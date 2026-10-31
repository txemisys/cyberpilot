import type {ReviewFinding,ReviewAction,ReviewEvidence} from "./finding-evidence-review";
export type ControlEventKind="finding-first"|"finding-last"|"finding-resolved"|"action-created"|"action-approved"|"action-started"|"action-completed"|"action-verified"|"step-acknowledged"|"evidence-captured"|"evidence-observed";
export type ControlChronologyEvent={
 id:string;
 findingId:string;
 actionId:string|null;
 evidenceId:string|null;
 at:Date;
 kind:ControlEventKind;
 title:string;
 detail:string;
 provenance:"finding"|"workflow"|"observed"|"declared"|"unknown"|"error";
 actionable:boolean;
};
export type ControlChronology={
 events:ControlChronologyEvent[];
 count:number;
 observations:number;
 workflowEvents:number;
 findingEvents:number;
 unknownEvidenceEvents:number;
 firstAt:Date|null;
 lastAt:Date|null;
 lastWorkAt:Date|null;
 lastObservationAt:Date|null;
 lastVerificationAt:Date|null;
 workAfterObservation:boolean;
 observationAfterWork:boolean;
 findingResolvedWithoutVerifiedAction:boolean;
 warnings:string[];
};
function valid(value:Date|null):value is Date{
 return value instanceof Date&&Number.isFinite(value.getTime());
}
function maximum(values:readonly(Date|null)[]):Date|null{
 const dates=values.filter(valid);
 if(!dates.length)return null;
 return dates.reduce((a,b)=>a.getTime()>=b.getTime()?a:b);
}
function minimum(values:readonly(Date|null)[]):Date|null{
 const dates=values.filter(valid);
 if(!dates.length)return null;
 return dates.reduce((a,b)=>a.getTime()<=b.getTime()?a:b);
}
function provenance(item:ReviewEvidence):ControlChronologyEvent["provenance"]{
 return item.source==="OBSERVED"?"observed":
  item.source==="DECLARED"?"declared":
  item.source==="ERROR"?"error":"unknown";
}
function actionEvents(findingId:string,action:ReviewAction):ControlChronologyEvent[]{
 const events:ControlChronologyEvent[]=[];
 const add=(at:Date|null,kind:ControlEventKind,title:string,detail:string)=>{
  if(!valid(at))return;
  events.push({
   id:action.id+":"+kind,actionId:action.id,findingId,evidenceId:null,
   at,kind,title,detail,provenance:"workflow",
   actionable:kind==="action-approved"||kind==="action-completed",
  });
 };
 add(action.createdAt,"action-created","Remediation proposed",
  action.title+" — "+action.mode);
 add(action.approvedAt,"action-approved","Remediation approved",
  "Approval was recorded, but no security change is proven.");
 add(action.startedAt,"action-started","Execution started",
  "The recorded action began execution.");
 add(action.completedAt,"action-completed","Work completed",
  "Execution completion does not independently verify the security finding.");
 add(action.status==="VERIFIED"?action.verifiedAt:null,"action-verified",
  "Workflow verification recorded",
  "A verified state and timestamp are both present. Review the finding state separately.");
 // Guided acknowledgement rows in the current review model have indices but
 // no timestamps. Avoid fabricating dates for these events.
 return events;
}
function evidenceEvents(findingId:string,item:ReviewEvidence):ControlChronologyEvent[]{
 const events:ControlChronologyEvent[]=[];
 const kind=provenance(item);
 if(valid(item.capturedAt)){
  events.push({
   id:item.id+":captured",findingId,actionId:null,evidenceId:item.id,
   at:item.capturedAt,kind:"evidence-captured",title:"Evidence record created",
   detail:item.summary,provenance:kind,actionable:kind!=="observed",
  });
 }
 if(valid(item.lastObservedAt)&&kind==="observed"){
  events.push({
   id:item.id+":observed",findingId,actionId:null,evidenceId:item.id,
   at:item.lastObservedAt,kind:"evidence-observed",title:"Observed control evidence",
   detail:item.summary,provenance:kind,actionable:true,
  });
 }
 return events;
}
export function buildControlChronology(finding:ReviewFinding):ControlChronology{
 const events:ControlChronologyEvent[]=[];
 const addFinding=(at:Date|null,kind:ControlEventKind,title:string,detail:string)=>{
  if(!valid(at))return;
  events.push({
   id:finding.id+":"+kind,findingId:finding.id,actionId:null,
   evidenceId:null,at,kind,title,detail,provenance:"finding",actionable:false,
  });
 };
 addFinding(finding.firstSeenAt,"finding-first","Finding first recorded",finding.title);
 addFinding(finding.lastSeenAt,"finding-last","Finding last observed",finding.description);
 addFinding(finding.status==="RESOLVED"?finding.resolvedAt:null,
  "finding-resolved","Finding resolved",
  "The finding is recorded as resolved; confirm supporting evidence and scope.");
 for(const action of finding.actions)events.push(...actionEvents(finding.id,action));
 for(const evidence of finding.evidence)events.push(...evidenceEvents(finding.id,evidence));
 events.sort((a,b)=>b.at.getTime()-a.at.getTime()||
  a.id.localeCompare(b.id));
 const workEvents=events.filter(event=>event.kind==="action-completed"||
  event.kind==="action-started");
 const observations=events.filter(event=>event.kind==="evidence-observed");
 const verified=events.filter(event=>event.kind==="action-verified");
 const lastWork=maximum(workEvents.map(x=>x.at));
 const lastObservation=maximum(observations.map(x=>x.at));
 const lastVerification=maximum(verified.map(x=>x.at));
 const workAfterObservation=Boolean(lastWork&&
  (!lastObservation||lastWork.getTime()>lastObservation.getTime()));
 const observationAfterWork=Boolean(lastWork&&lastObservation&&
  lastObservation.getTime()>=lastWork.getTime());
 const resolutionWithoutVerification=finding.status==="RESOLVED"&&verified.length===0;
 const warnings:string[]=[];
 if(workAfterObservation)warnings.push(
  "Recorded remediation work is newer than the last matched observation.",
 );
 if(lastWork&&!lastObservation)warnings.push(
  "There is no dated observed control evidence following the remediation.",
 );
 if(resolutionWithoutVerification)warnings.push(
  "The finding is resolved, but no verified remediation action appears in this bounded history.",
 );
 if(finding.evidence.some(item=>item.source==="DECLARED"))warnings.push(
  "Declared evidence is not an independent observation of the affected control.",
 );
 if(finding.evidence.some(item=>item.source==="UNKNOWN"||item.source==="ERROR"))
  warnings.push("Inconclusive evidence must be investigated separately.");
 return {
  events,count:events.length,
  observations:observations.length,
  workflowEvents:events.filter(x=>x.provenance==="workflow").length,
  findingEvents:events.filter(x=>x.provenance==="finding").length,
  unknownEvidenceEvents:events.filter(x=>
   x.provenance==="error"||x.provenance==="unknown").length,
  firstAt:minimum(events.map(x=>x.at)),
  lastAt:maximum(events.map(x=>x.at)),
  lastWorkAt:lastWork,
  lastObservationAt:lastObservation,
  lastVerificationAt:lastVerification,
  workAfterObservation,
  observationAfterWork,
  findingResolvedWithoutVerifiedAction:resolutionWithoutVerification,
  warnings,
 };
}
export function filterControlChronology(
 chronology:ControlChronology,
 filter:"all"|"finding"|"workflow"|"evidence",
):ControlChronologyEvent[]{
 if(filter==="all")return [...chronology.events];
 if(filter==="evidence")return chronology.events.filter(item=>
  item.provenance!=="finding"&&item.provenance!=="workflow");
 return chronology.events.filter(item=>item.provenance===filter);
}
export function exportControlChronologyText(
 finding:ReviewFinding,
 chronology:ControlChronology,
):string{
 const text=[
  "CYBERPILOT — CONTROL EVIDENCE CHRONOLOGY",
  "Historical operational records; not proof of security compliance.",
  "Finding: "+finding.title,
  "Severity: "+finding.severity,
  "Finding status: "+finding.status,
  "Timeline events: "+chronology.count,
  "Last remediation work: "+(chronology.lastWorkAt?.toISOString()??"Not recorded"),
  "Last matched observation: "+(chronology.lastObservationAt?.toISOString()??"Not recorded"),
  "Last action verification: "+(chronology.lastVerificationAt?.toISOString()??"Not recorded"),
  "",
  "LIMITATIONS",
  ...(chronology.warnings.length?chronology.warnings.map(x=>"- "+x):
   ["- Scope and conclusions still require review."]),
  "",
  "RECORDED EVENTS (newest first)",
 ];
 for(const item of chronology.events)text.push(
  item.at.toISOString()+" | "+item.provenance+" | "+item.title,
  "  "+item.detail,
 );
 return text.join("\n")+"\n";
}
