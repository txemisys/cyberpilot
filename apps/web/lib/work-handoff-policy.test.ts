import {describe,expect,it} from "vitest";
import {
 HandoffError,assertHandoffPermission,assertPendingHandoff,
 canCancelHandoff,canDecideHandoff,canRequestHandoff,handoffExpiry,
 handoffId,handoffLabel,handoffPriority,handoffReason,handoffResponse,
 handoffRevision,handoffSummary,handoffTaskWarning,orderHandoffs,
 parseHandoffCommand,type HandoffRecord
} from "./work-handoff-policy";
const now=new Date("2026-10-31T12:00:00.000Z");
const id="clhandoff123";
const req={kind:"request",workItemId:"clwork12345",recipientUserId:"cluser12345",
 reason:"Please take responsibility for this remediation",expiresAt:"2026-11-15"};
const record=(overrides:Partial<HandoffRecord>={}):HandoffRecord=>({
 id,workItemId:"clwork12345",requesterUserId:"clrequester1",
 recipientUserId:"clrecipient1",status:"REQUESTED",revision:1,
 requestedAt:new Date("2026-10-30"),expiresAt:null,...overrides
});
describe("handoff parsing",()=>{
 it("parses valid requests and expiry",()=>{
  const parsed=parseHandoffCommand(req,now);
  expect(parsed.kind).toBe("request");
  if(parsed.kind==="request"){
   expect(parsed.reason).toBe(req.reason);
   expect(parsed.expiresAt?.toISOString()).toContain("2026-11-15");
  }
 });
 it("rejects malformed request structures",()=>{
  for(const invalid of [null,undefined,[],42,"request"])
   expect(()=>parseHandoffCommand(invalid,now)).toThrow(HandoffError);
 });
 it("rejects unknown and server-owned fields",()=>{
  expect(()=>parseHandoffCommand({...req,organizationId:"other"},now)).toThrow();
  expect(()=>parseHandoffCommand({...req,status:"ACCEPTED"},now)).toThrow();
  expect(()=>parseHandoffCommand({...req,decidedAt:now},now)).toThrow();
 });
 it("validates identifiers consistently",()=>{
  expect(handoffId("clwork12345")).toBe("clwork12345");
  for(const value of ["",null,12,{},[],"../cross","a".repeat(101)])
   expect(()=>handoffId(value)).toThrow();
 });
 it("enforces meaningful reason text",()=>{
  expect(handoffReason("  Please review this remediation  ")).toBe("Please review this remediation");
  for(const invalid of ["", "short",null,1,"a".repeat(2001),"invalid\u0000note"])
   expect(()=>handoffReason(invalid)).toThrow();
 });
 it("allows empty response but limits text",()=>{
  expect(handoffResponse("")).toBe("");
  expect(handoffResponse("  Reviewed  ")).toBe("Reviewed");
  expect(()=>handoffResponse("a".repeat(2001))).toThrow();
  expect(()=>handoffResponse(null)).toThrow();
 });
 it("requires concrete positive integer revisions",()=>{
  expect(handoffRevision(1)).toBe(1);
  for(const invalid of [0,-1,1.2,"1",null,2147483648,NaN])
   expect(()=>handoffRevision(invalid)).toThrow();
 });
 it("rejects past, malformed and excessively distant deadlines",()=>{
  for(const invalid of ["2026-10-30","2027-05-01","2026-02-30","2026-2-1","tomorrow",true])
   expect(()=>handoffExpiry(invalid,now)).toThrow();
  expect(handoffExpiry(null,now)).toBeNull();
  expect(handoffExpiry(undefined,now)).toBeNull();
 });
 it("parses acceptance and decline decisions",()=>{
  expect(parseHandoffCommand({
   kind:"decide",handoffId:id,revision:3,decision:"ACCEPTED",response:"Accepted"
  },now)).toMatchObject({kind:"decide",revision:3,decision:"ACCEPTED"});
  expect(parseHandoffCommand({
   kind:"decide",handoffId:id,revision:3,decision:"DECLINED"
  },now)).toMatchObject({kind:"decide",decision:"DECLINED",response:""});
 });
 it("rejects attempts to forge other handoff states",()=>{
  for(const decision of ["REQUESTED","CANCELLED","VERIFIED",null])
   expect(()=>parseHandoffCommand({
    kind:"decide",handoffId:id,revision:1,decision
   },now)).toThrow();
 });
 it("accepts cancellations with explicit concurrency version",()=>{
  expect(parseHandoffCommand({
   kind:"cancel",handoffId:id,revision:1,response:"Cancelled after reassignment"
  },now)).toMatchObject({kind:"cancel",revision:1});
 });
});
describe("handoff authorization",()=>{
 it("only lets managers issue new ownership requests",()=>{
  expect(canRequestHandoff("OWNER")).toBe(true);
  expect(canRequestHandoff("ADMIN")).toBe(true);
  expect(canRequestHandoff("MEMBER")).toBe(false);
  expect(canRequestHandoff("AUDITOR")).toBe(false);
 });
 it("requires explicit decision by the actual recipient",()=>{
  expect(canDecideHandoff("MEMBER","recipient","recipient")).toBe(true);
  expect(canDecideHandoff("ADMIN","recipient","other")).toBe(false);
  expect(canDecideHandoff("OWNER","recipient","other")).toBe(false);
  expect(canDecideHandoff("AUDITOR","recipient","recipient")).toBe(false);
 });
 it("allows managers and requester to cancel but not unrelated members",()=>{
  expect(canCancelHandoff("OWNER",null,"manager")).toBe(true);
  expect(canCancelHandoff("ADMIN",null,"manager")).toBe(true);
  expect(canCancelHandoff("MEMBER","requester","requester")).toBe(true);
  expect(canCancelHandoff("MEMBER","other","requester")).toBe(false);
  expect(canCancelHandoff("AUDITOR","requester","requester")).toBe(false);
 });
 it("enforces operation-specific decisions",()=>{
  expect(()=>assertHandoffPermission("OWNER","request","actor",null,"recipient")).not.toThrow();
  expect(()=>assertHandoffPermission("MEMBER","request","actor",null,"recipient")).toThrow();
  expect(()=>assertHandoffPermission("MEMBER","decide","recipient","other","recipient")).not.toThrow();
  expect(()=>assertHandoffPermission("ADMIN","decide","actor",null,"recipient")).toThrow();
  expect(()=>assertHandoffPermission("AUDITOR","cancel","actor","actor","recipient")).toThrow();
 });
});
describe("handoff workflow and stale updates",()=>{
 it("allows pending current versions to be decided",()=>{
  expect(()=>assertPendingHandoff(record(),1,now)).not.toThrow();
 });
 it("blocks stale versions and already decided requests",()=>{
  expect(()=>assertPendingHandoff(record(),2,now)).toThrow(HandoffError);
  for(const status of ["ACCEPTED","DECLINED","CANCELLED"] as const)
   expect(()=>assertPendingHandoff(record({status}),1,now)).toThrow();
 });
 it("rejects expired pending requests",()=>{
  expect(()=>assertPendingHandoff(record({expiresAt:new Date("2026-10-30")}),1,now)).toThrow();
 });
 it("allows cancelling expired pending requests but not accepting them",()=>{
  const expired=record({expiresAt:new Date("2026-10-30")});
  expect(()=>assertPendingHandoff(expired,1,now,false)).toThrow();
  expect(()=>assertPendingHandoff(expired,1,now,true)).not.toThrow();
  expect(()=>assertPendingHandoff({...expired,status:"ACCEPTED"},1,now,true)).toThrow();
 });
 it("labels expired requests without altering stored state",()=>{
  expect(handoffLabel(record({expiresAt:new Date("2026-10-30")}),now)).toBe("EXPIRED");
  expect(handoffLabel(record(),now)).toBe("AWAITING_RESPONSE");
  expect(handoffLabel(record({status:"ACCEPTED"}),now)).toBe("ACCEPTED");
 });
 it("keeps work completion separate from finding closure",()=>{
  expect(handoffTaskWarning("ACCEPTED","DONE")).toContain("does not indicate");
  expect(handoffTaskWarning("REQUESTED","TODO")).toContain("not transferred");
  expect(handoffTaskWarning("DECLINED","TODO")).toBeNull();
 });
 it("summarizes pending, expired and recorded decisions",()=>{
  const rows=[
   record(),record({id:"clhandoff124",expiresAt:new Date("2026-10-30")}),
   record({id:"clhandoff125",status:"ACCEPTED"}),
   record({id:"clhandoff126",status:"DECLINED"}),
   record({id:"clhandoff127",status:"CANCELLED"})
  ];
  expect(handoffSummary(rows,now)).toEqual({
   total:5,awaiting:1,expired:1,accepted:1,declined:1,cancelled:1
  });
 });
 it("prioritizes expired and pending decisions",()=>{
  const rows=[
   record({id:"clhandoff125",status:"ACCEPTED"}),
   record({id:"clhandoff123"}),
   record({id:"clhandoff124",expiresAt:new Date("2026-10-30")})
  ];
  expect(orderHandoffs(rows,now).map(x=>x.id)).toEqual([
   "clhandoff124","clhandoff123","clhandoff125"
  ]);
  expect(handoffPriority(rows[2]!,now)).toBe(0);
 });
});
