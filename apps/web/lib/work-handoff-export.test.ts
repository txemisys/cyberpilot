import {describe,expect,it} from "vitest";
import {
 HANDOFF_COLUMNS,csvHandoffCell,handoffDate,handoffValues,serializeHandoffs,
 summarizeHandoffExport,classifyHandoffAttention,prioritizeHandoffAttention,
 groupHandoffInbox,type HandoffExportRow,type HandoffInboxRow
} from "./work-handoff-export";
const now=new Date("2026-10-31T12:00:00.000Z");
const example:HandoffExportRow={
 id:"clhandoff123",workItemId:"clwork12345",status:"REQUESTED",
 reason:"Transfer work to security team",response:null,revision:1,
 requester:{name:"Manager",email:"manager@example.org"},
 recipient:{name:"Analyst",email:"analyst@example.org"},decider:null,
 workItem:{title:"Review MFA coverage",status:"IN_PROGRESS",
  finding:{title:"MFA gap",status:"OPEN",severity:"HIGH"}},
 requestedAt:new Date("2026-10-30"),decidedAt:null,expiresAt:new Date("2026-11-05")
};
const inbox=(id:string,changes:Partial<HandoffInboxRow>={}):HandoffInboxRow=>({
 id,recipientUserId:"user12345",requesterUserId:"manager123",
 status:"REQUESTED",requestedAt:new Date("2026-10-30"),expiresAt:null,
 workItem:{status:"TODO",priority:"HIGH",dueAt:null},...changes
});
describe("handoff export",()=>{
 it("preserves distinct work and finding states",()=>{
  expect(HANDOFF_COLUMNS).toHaveLength(20);
  expect(HANDOFF_COLUMNS).toContain("Work state");
  expect(HANDOFF_COLUMNS).toContain("Finding state");
  expect(HANDOFF_COLUMNS).not.toContain("Verified");
 });
 it("serializes all fields",()=>{
  const values=handoffValues(example);
  expect(values).toHaveLength(20);
  expect(values[0]).toBe(example.id);
  expect(values[7]).toBe("REQUESTED");
  expect(values[13]).toBe("analyst@example.org");
  expect(values[19]).toBe(1);
 });
 it("quotes CSV and resists formula injection",()=>{
  for(const value of ["=1+1","-3+4","+SUM(A1:A3)","@SUM(1)","  =HYPERLINK(1)"]){
   expect(csvHandoffCell(value)).toBe(`"'${value}"`);
  }
  expect(csvHandoffCell('Quoted "field"')).toBe('"Quoted ""field"""');
 });
 it("serializes UTC date and missing decision",()=>{
  expect(handoffDate(null)).toBe("");
  expect(handoffDate(now)).toBe("2026-10-31T12:00:00.000Z");
  expect(handoffValues(example)[18]).toBe("");
 });
 it("returns header-only CSV when empty",()=>{
  expect(serializeHandoffs([]).split("\r\n")).toHaveLength(2);
 });
 it("keeps multiline rationale as quoted data",()=>{
  const csv=serializeHandoffs([{...example,reason:"Line one\nLine two"}]);
  expect(csv).toContain('"Line one\nLine two"');
  expect(csv.endsWith("\r\n")).toBe(true);
 });
 it("counts accepted work separately from finding closure",()=>{
  const summary=summarizeHandoffExport([
   example,{...example,id:"clhandoff124",status:"ACCEPTED",
    workItem:{...example.workItem,status:"DONE"}}
  ]);
  expect(summary).toMatchObject({
   total:2,requested:1,accepted:1,acceptedWithOpenFindings:1,
   completedWorkWithOpenFindings:1
  });
  expect(summary.note).toContain("not remediation verification");
 });
});
describe("recipient attention and work deadlines",()=>{
 it("identifies expired requests first",()=>{
  expect(classifyHandoffAttention(inbox("handoff01",{
   expiresAt:new Date("2026-10-30")
  }),now)).toMatchObject({urgency:"EXPIRED",actionable:false});
 });
 it("identifies overdue work awaiting assignment",()=>{
  expect(classifyHandoffAttention(inbox("handoff01",{
   workItem:{status:"TODO",priority:"HIGH",dueAt:new Date("2026-10-30")}
  }),now)).toMatchObject({urgency:"OVERDUE_WORK",actionable:true});
 });
 it("identifies imminent deadlines",()=>{
  expect(classifyHandoffAttention(inbox("handoff01",{
   workItem:{status:"IN_PROGRESS",priority:"HIGH",dueAt:new Date("2026-11-03")}
  }),now).urgency).toBe("DUE_SOON");
 });
 it("does not flag completed work as overdue",()=>{
  expect(classifyHandoffAttention(inbox("handoff01",{
   workItem:{status:"DONE",priority:"LOW",dueAt:new Date("2026-10-01")}
  }),now).urgency).toBe("AWAITING");
 });
 it("ranks expired, overdue, soon and pending cases",()=>{
  const rows=[
   inbox("pending01"),
   inbox("soon0001",{workItem:{status:"TODO",priority:"HIGH",dueAt:new Date("2026-11-02")}}),
   inbox("expired1",{expiresAt:new Date("2026-10-01")}),
   inbox("overdue1",{workItem:{status:"TODO",priority:"HIGH",dueAt:new Date("2026-10-01")}})
  ];
  expect(prioritizeHandoffAttention(rows,now).map(x=>x.id))
   .toEqual(["expired1","overdue1","soon0001","pending01"]);
 });
 it("groups actionable work by intended recipient",()=>{
  const rows=[
   inbox("handoff01"),
   inbox("handoff02",{workItem:{status:"TODO",priority:"HIGH",dueAt:new Date("2026-10-01")}}),
   inbox("handoff03",{recipientUserId:"other123",expiresAt:new Date("2026-10-01")})
  ];
  expect(groupHandoffInbox(rows,now)).toEqual([
   {recipientUserId:"user12345",total:2,waiting:2,overdue:1,expiring:0},
   {recipientUserId:"other123",total:1,waiting:0,overdue:0,expiring:1}
  ]);
 });
});
