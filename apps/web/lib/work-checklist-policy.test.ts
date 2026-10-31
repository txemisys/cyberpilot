import {describe,expect,it} from "vitest";
import {
 ChecklistError,canAcknowledgeChecklist,canStructureChecklist,
 checklistDescription,checklistId,checklistNextPosition,checklistPermissions,
 checklistProgress,checklistTitle,describeChecklistAction,
 parseChecklistEntry,parseChecklistOperation,parseChecklistPatch,
 summarizeChecklistActivity,validateChecklistReorder
} from "./work-checklist-policy";
const work="clwork12345678",entry="clentry12345678";
const makeAdd=()=>({kind:"add" as const,workItemId:work,entry:{
 title:"Review conditional access settings",description:"Coordinate review with operations"
}});
describe("checklist tenant boundary input validation",()=>{
 it("requires valid work IDs and entry IDs",()=>{
  expect(checklistId(work)).toBe(work);
  expect(checklistId(entry)).toBe(entry);
  for(const invalid of ["",null,undefined,3,{},[],"../other","x","abc","!@#$","a".repeat(101)])
   expect(()=>checklistId(invalid)).toThrow(ChecklistError);
 });
 it("does not allow payloads to set organization or actors",()=>{
  expect(()=>parseChecklistOperation({...makeAdd(),organizationId:"outside"})).toThrow(/Unsupported/);
  expect(()=>parseChecklistOperation({...makeAdd(),actorUserId:"outside"})).toThrow(/Unsupported/);
  expect(()=>parseChecklistOperation({...makeAdd(),entry:{
   ...makeAdd().entry,completedByUserId:"outside"
  }})).toThrow(/Unsupported/);
 });
 it("validates required titles and trims whitespace",()=>{
  expect(checklistTitle("  Review incident steps  ")).toBe("Review incident steps");
  for(const invalid of ["", " x ", "x".repeat(181),null,undefined,20,[],{}, "Bad\u0001title"])
   expect(()=>checklistTitle(invalid)).toThrow();
 });
 it("allows useful multiline instructions but not control characters",()=>{
  expect(checklistDescription("  First\nSecond  ")).toBe("First\nSecond");
  expect(checklistDescription("")).toBe("");
  for(const invalid of [null,1,{}, "z".repeat(3001),"a\u0000b"])
   expect(()=>checklistDescription(invalid)).toThrow();
 });
 it("rejects unexpected fields when adding entries",()=>{
  expect(()=>parseChecklistEntry({title:"A valid task",verifiedAt:"2026-10-31"})).toThrow();
  expect(()=>parseChecklistEntry({title:"A valid task",status:"VERIFIED"})).toThrow();
  expect(()=>parseChecklistEntry(null)).toThrow();
  expect(()=>parseChecklistEntry([])).toThrow();
 });
 it("uses empty description by default without inventing work",()=>{
  expect(parseChecklistEntry({title:"  Review MFA  "})).toEqual({
   title:"Review MFA",description:""
  });
 });
 it("updates only recognized fields",()=>{
  expect(parseChecklistPatch({title:"  Updated title  "})).toEqual({title:"Updated title"});
  expect(parseChecklistPatch({description:" new\nsteps "})).toEqual({description:"new\nsteps"});
  expect(()=>parseChecklistPatch({})).toThrow();
  expect(()=>parseChecklistPatch({completedAt:"2026-01-01"})).toThrow();
 });
});
describe("supported operations",()=>{
 it("parses add operations",()=>{
  const parsed=parseChecklistOperation(makeAdd());
  expect(parsed.kind).toBe("add");
  if(parsed.kind==="add")expect(parsed.entry.title).toBe("Review conditional access settings");
 });
 it("parses edit operations and trims values",()=>{
  const parsed=parseChecklistOperation({
   kind:"edit",workItemId:work,entryId:entry,entry:{title:"  Updated review steps  "}
  });
  expect(parsed.kind).toBe("edit");
  if(parsed.kind==="edit")expect(parsed.entry.title).toBe("Updated review steps");
 });
 it("requires boolean completion inputs",()=>{
  for(const invalid of [null,0,1,"true","false",{},undefined])
   expect(()=>parseChecklistOperation({
    kind:"toggle",workItemId:work,entryId:entry,completed:invalid
   })).toThrow();
  expect(parseChecklistOperation({
   kind:"toggle",workItemId:work,entryId:entry,completed:true
  })).toMatchObject({kind:"toggle",completed:true});
 });
 it("parses remove operations without implicit destructive flags",()=>{
  expect(parseChecklistOperation({
   kind:"remove",workItemId:work,entryId:entry
  })).toEqual({kind:"remove",workItemId:work,entryId:entry});
  expect(()=>parseChecklistOperation({
   kind:"remove",workItemId:work,entryId:entry,deleteWorkItem:true
  })).toThrow();
 });
 it("rejects unknown mutation types",()=>{
  for(const kind of ["verify","resolve","approve","cancel","delete","execute",null])
   expect(()=>parseChecklistOperation({kind,workItemId:work})).toThrow();
 });
 it("rejects duplicate and malformed reorder IDs",()=>{
  expect(()=>parseChecklistOperation({
   kind:"reorder",workItemId:work,entryIds:[entry,entry]
  })).toThrow();
  expect(()=>parseChecklistOperation({
   kind:"reorder",workItemId:work,entryIds:["!"]
  })).toThrow();
  expect(()=>parseChecklistOperation({
   kind:"reorder",workItemId:work,entryIds:"not an array"
  })).toThrow();
 });
 it("rejects reorder requests longer than the cap",()=>{
  const ids=Array.from({length:101},(_,i)=>"entry"+String(i).padStart(5,"0"));
  expect(()=>parseChecklistOperation({
   kind:"reorder",workItemId:work,entryIds:ids
  })).toThrow();
 });
 it("normalizes allowed reordering input",()=>{
  const ids=[entry,"clentry98765432"];
  expect(parseChecklistOperation({
   kind:"reorder",workItemId:work,entryIds:ids
  })).toEqual({kind:"reorder",workItemId:work,entryIds:ids});
 });
});
describe("role restrictions and authorized acknowledgment",()=>{
 it("only lets managers change checklist structure",()=>{
  expect(canStructureChecklist("OWNER")).toBe(true);
  expect(canStructureChecklist("ADMIN")).toBe(true);
  expect(canStructureChecklist("MEMBER")).toBe(false);
  expect(canStructureChecklist("AUDITOR")).toBe(false);
 });
 it("allows the assigned member to acknowledge their own work",()=>{
  expect(canAcknowledgeChecklist("MEMBER","assigned123","assigned123")).toBe(true);
  expect(canAcknowledgeChecklist("MEMBER","other123","assigned123")).toBe(false);
  expect(canAcknowledgeChecklist("MEMBER",null,"assigned123")).toBe(false);
 });
 it("does not let auditors acknowledge work even if assigned",()=>{
  expect(canAcknowledgeChecklist("AUDITOR","assigned123","assigned123")).toBe(false);
 });
 it("allows owners and admins to acknowledge unassigned work",()=>{
  expect(canAcknowledgeChecklist("OWNER",null,"manager123")).toBe(true);
  expect(canAcknowledgeChecklist("ADMIN",null,"manager123")).toBe(true);
 });
 it("rejects MEMBER structural mutations",()=>{
  for(const kind of ["add","edit","remove","reorder"] as const)
   expect(()=>checklistPermissions("MEMBER","actor123","actor123",kind)).toThrow(ChecklistError);
 });
 it("blocks cross-assignee completion",()=>{
  expect(()=>checklistPermissions("MEMBER","other123","actor123","toggle")).toThrow();
  expect(()=>checklistPermissions("AUDITOR","actor123","actor123","toggle")).toThrow();
  expect(()=>checklistPermissions("MEMBER",null,"actor123","toggle")).toThrow();
 });
 it("allows permitted operations",()=>{
  expect(()=>checklistPermissions("OWNER",null,"actor123","add")).not.toThrow();
  expect(()=>checklistPermissions("ADMIN",null,"actor123","reorder")).not.toThrow();
  expect(()=>checklistPermissions("MEMBER","actor123","actor123","toggle")).not.toThrow();
 });
});
describe("reorder invariants and checklist capacity",()=>{
 const a="clentryAAA",b="clentryBBB",c="clentryCCC";
 it("permits a permutation of the exact same entries",()=>{
  expect(()=>validateChecklistReorder([a,b,c],[c,a,b])).not.toThrow();
 });
 it("rejects missing and extra entries",()=>{
  expect(()=>validateChecklistReorder([a,b,c],[a,b])).toThrow();
  expect(()=>validateChecklistReorder([a,b],[a,b,c])).toThrow();
  expect(()=>validateChecklistReorder([a,b],[a,c])).toThrow();
 });
 it("rejects duplicate IDs",()=>{
  expect(()=>validateChecklistReorder([a,b],[a,a])).toThrow();
 });
 it("chooses the next free monotonic position",()=>{
  expect(checklistNextPosition([])).toBe(0);
  expect(checklistNextPosition([0,1,5])).toBe(6);
  expect(checklistNextPosition([3,8,2])).toBe(9);
 });
 it("enforces the maximum of 100 checklist entries",()=>{
  expect(()=>checklistNextPosition(Array.from({length:100},(_,i)=>i))).toThrow();
  expect(()=>checklistNextPosition([2147483646])).toThrow();
 });
});
describe("human work progress semantics",()=>{
 const complete=new Date("2026-10-31T08:00:00.000Z");
 it("does not treat an empty checklist as acknowledged",()=>{
  expect(checklistProgress([])).toEqual({
   total:0,completed:0,remaining:0,percent:0,hasOutstanding:false,
   allAcknowledged:false
  });
 });
 it("tracks partial work completion",()=>{
  expect(checklistProgress([
   {completedAt:complete},{completedAt:null},{completedAt:null}
  ])).toEqual({
   total:3,completed:1,remaining:2,percent:33,hasOutstanding:true,
   allAcknowledged:false
  });
 });
 it("keeps acknowledgment independent of finding state",()=>{
  expect(checklistProgress([{completedAt:complete},{completedAt:complete}])).toMatchObject({
   total:2,completed:2,remaining:0,percent:100,allAcknowledged:true
  });
 });
 it("provides legible event descriptions",()=>{
  const operations=[
   makeAdd(),
   {kind:"edit",workItemId:work,entryId:entry,entry:{title:"Update title"}},
   {kind:"toggle",workItemId:work,entryId:entry,completed:true},
   {kind:"toggle",workItemId:work,entryId:entry,completed:false},
   {kind:"remove",workItemId:work,entryId:entry},
   {kind:"reorder",workItemId:work,entryIds:[entry]}
  ] as const;
  expect(operations.map(x=>describeChecklistAction(x))).toEqual([
   "Added a coordination checklist entry","Updated checklist instructions",
   "Acknowledged checklist work","Reopened checklist work",
   "Removed a checklist entry","Reordered checklist entries"
  ]);
 });
 it("summarizes recent activity without treating it as security results",()=>{
  const now=new Date("2026-10-31T12:00:00.000Z");
  const results=summarizeChecklistActivity([
   {kind:"UPDATED",actorUserId:"actor1",occurredAt:new Date("2026-10-30")},
   {kind:"UPDATED",actorUserId:"actor1",occurredAt:new Date("2026-10-29")},
   {kind:"UPDATED",actorUserId:"actor2",occurredAt:new Date("2026-10-28")},
   {kind:"UPDATED",actorUserId:"actor2",occurredAt:new Date("2026-09-28")}
  ],now);
  expect(results.recent).toBe(3);
  expect(results.byActor).toEqual([
   {actorUserId:"actor1",count:2},{actorUserId:"actor2",count:1}
  ]);
 });
});
