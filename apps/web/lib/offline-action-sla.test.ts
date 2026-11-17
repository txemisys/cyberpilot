import{describe,it,expect}from "vitest";
import{defaultSlaCalendar,defaultSlaRules,validateSlaPolicy,
 businessMinutesBetween,addBusinessMinutes,buildSlaOperationalReport,
 verifySlaOperationalReport,filterSlaSignals,compareSlaReports,
 exportSlaOperationalReport}from "./offline-action-sla";
import type{ActionSnapshot,ActionDomainEvent}from "./integrated-action-domain";
const at="2026-11-17T10:00:00.000Z";
function action():ActionSnapshot{
 return{
  organizationId:"org-test",actionId:"action-test",
  riskKey:"a".repeat(64),title:"Backup not tested",
  description:"Operator follow-up",severity:"HIGH",
  sourceFingerprint:"b".repeat(64),evidenceRefs:[],
  status:"BLOCKED",priority:"HIGH",
  ownerUserId:null,dueAt:"2026-11-16T10:00:00.000Z",
  rationale:"Operational block",
  exceptionReason:null,exceptionExpiresAt:null,
  revision:1,createdById:"member-one",updatedById:"member-one",
  updatedAt:"2026-11-13T10:00:00.000Z",
  independentRemediationVerified:false,
  customerLegalAcceptanceProven:false,sourceEvidenceReevaluated:false,
 };
}
function event():ActionDomainEvent{
 return{
  organizationId:"org-test",actionId:"action-test",
  revision:1,kind:"CREATE",previousStatus:"OPEN",
  nextStatus:"BLOCKED",actorUserId:"member-one",
  occurredAt:"2026-11-13T10:00:00.000Z",
  snapshotDigest:"c".repeat(64),
  automaticallyExecutedRemediation:false,
 };
}
function report(asOf=at){
 return buildSlaOperationalReport({
  organizationId:"org-test",asOf,actions:[action()],
  events:[event()],calendar:defaultSlaCalendar(),
  rules:defaultSlaRules(),actionLimit:500,eventLimit:2000,
  truncatedActions:false,truncatedEvents:false,
 });
}
describe("offline action SLA board",()=>{
 it("validates local hours and rejects invented calendars",()=>{
  const calendar=defaultSlaCalendar();
  expect(validateSlaPolicy(calendar,defaultSlaRules())).toEqual([]);
  calendar.workingDays=[1,1];
  expect(validateSlaPolicy(calendar,defaultSlaRules()))
   .toContain("WORK_DAYS_INVALID");
 });
 it("calculates business minutes across a weekend",()=>{
  const calendar=defaultSlaCalendar();
  const before="2026-11-13T15:00:00.000Z";
  const after="2026-11-16T09:00:00.000Z";
  expect(businessMinutesBetween(before,after,calendar)).toBe(180);
  expect(addBusinessMinutes(before,180,calendar)).toBe(after);
 });
 it("reports overdue blocked and unowned action without sending messages",()=>{
  const value=report();
  expect(value.state).toBe("REVIEW_REQUIRED");
  expect(value.overview.unowned).toBe(1);
  expect(value.overview.blocked).toBe(1);
  expect(value.signals.some(x=>x.code==="NO_OWNER")).toBe(true);
  expect(value.signals.some(x=>x.code==="COMPLETION_OVERDUE")).toBe(false);
  expect(value.signals.some(x=>x.code==="EVIDENCE_UNLINKED")).toBe(true);
  expect(value.externalNotificationsDispatched).toBe(false);
  expect(verifySlaOperationalReport(value,"org-test").valid).toBe(true);
 });
 it("requires complete CAS history for action monitoring",()=>{
  const data=report();
  data.rows[0]!.revision=3;
  expect(verifySlaOperationalReport(data).valid).toBe(false);
  const input=buildSlaOperationalReport({
   organizationId:"org-test",asOf:at,actions:[{...action(),revision:3}],
   events:[event()],calendar:defaultSlaCalendar(),
   rules:defaultSlaRules(),actionLimit:500,eventLimit:2000,
   truncatedActions:false,truncatedEvents:false,
  });
  expect(input.state).toBe("INCOMPLETE");
  expect(input.overview.auditDefects).toBeGreaterThan(0);
 });
 it("rejects cross-tenant sources",()=>{
  expect(()=>buildSlaOperationalReport({
   organizationId:"org-test",asOf:at,
   actions:[{...action(),organizationId:"foreign-org"}],
   events:[event()],calendar:defaultSlaCalendar(),
   rules:defaultSlaRules(),actionLimit:500,eventLimit:2000,
   truncatedActions:false,truncatedEvents:false,
  })).toThrow("CROSS_TENANT");
 });
 it("filters signals and exports without claiming provider actions",()=>{
  const value=report();
  expect(filterSlaSignals(value,{levels:["URGENT"]}).every(x=>
   x.level==="URGENT")).toBe(true);
  expect(exportSlaOperationalReport(value,"CSV").content)
   .toContain("NO_OWNER");
  expect(JSON.parse(exportSlaOperationalReport(value,"JSON").content)
   .overview.verifiedRemediations).toBe(0);
 });
 it("compares two local cuts without implying remediation",()=>{
  const first=report();
  const next=report("2026-11-17T11:00:00.000Z");
  const comparison=compareSlaReports(first,next);
  expect(comparison.noLongerDetectedMeansRemediated).toBe(false);
  expect(comparison.notificationsSent).toBe(false);
 });
});
