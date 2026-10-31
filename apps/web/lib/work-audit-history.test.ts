import {describe,expect,it} from "vitest";
import {
 HistoryInputError,historyIdentifier,encodeHistoryCursor,decodeHistoryCursor,
 parseHistoryFilter,historyOrderWhere,makeHistoryPage,
 histogramHistory,activityDayBuckets,activityByActor,
 auditExportCell,serializeAuditHistory,AUDIT_COLUMNS,type HistoryRow
} from "./work-audit-history";
const at=new Date("2026-10-31T12:00:00.000Z");
const item=(id:string,kind="UPDATED",when=at):HistoryRow=>({
 id,kind,occurredAt:when,actorUserId:"actor12345",comment:"Work state updated"
});
describe("history cursor validation",()=>{
 it("uses canonical date and opaque ID",()=>{
  const token=encodeHistoryCursor({occurredAt:at,id:"clhistory001"});
  expect(token).toBe("2026-10-31T12:00:00.000Z|clhistory001");
  expect(decodeHistoryCursor(token)).toEqual({occurredAt:at,id:"clhistory001"});
 });
 it("rejects invalid and noncanonical cursors",()=>{
  for(const invalid of [
   10,{},[],"invalid","2026-02-30T00:00:00.000Z|clhistory01",
   "2026-10-31|clhistory01","2026-10-31T12:00:00.000Z|../bad",
   "2026-10-31T12:00:00.000Z|clhistory01|extra",
   "a".repeat(200)
  ])expect(()=>decodeHistoryCursor(invalid)).toThrow(HistoryInputError);
 });
 it("supports initial page without a cursor",()=>{
  expect(decodeHistoryCursor("")).toBeNull();
  expect(decodeHistoryCursor(null)).toBeNull();
  expect(decodeHistoryCursor(undefined)).toBeNull();
 });
 it("validates work and actor identifiers",()=>{
  expect(historyIdentifier("clwork12345")).toBe("clwork12345");
  for(const invalid of ["",null,1,"../tenant","!","x".repeat(101)])
   expect(()=>historyIdentifier(invalid)).toThrow();
 });
 it("constructs exclusive newest-first continuation",()=>{
  const where=historyOrderWhere({occurredAt:at,id:"clhistory001"});
  expect(where.OR).toHaveLength(2);
  expect(where.OR?.[1]).toMatchObject({id:{lt:"clhistory001"}});
 });
 it("has no cursor restriction for first page",()=>{
  expect(historyOrderWhere(null)).toEqual({});
 });
});
describe("history filter boundary",()=>{
 it("defaults to safe first-page settings",()=>{
  expect(parseHistoryFilter({})).toEqual({
   limit:25,cursor:null,kind:null,actorUserId:null,search:""
  });
 });
 it("supports explicit filters",()=>{
  const result=parseHistoryFilter({
   kind:"COMMENTED",actor:"actor12345",search:"  handoff ",limit:"50"
  });
  expect(result).toMatchObject({
   limit:50,kind:"COMMENTED",actorUserId:"actor12345",search:"handoff"
  });
 });
 it("rejects inflated or invalid sizes",()=>{
  for(const invalid of ["0","101","-1","x","1.2","99999999999",false])
   expect(()=>parseHistoryFilter({limit:invalid})).toThrow();
 });
 it("rejects unexpected query keys",()=>{
  for(const key of ["organizationId","workItemId","status","permission"]){
   expect(()=>parseHistoryFilter({[key]:"outside"})).toThrow();
  }
 });
 it("rejects unsupported event types",()=>{
  for(const invalid of ["VERIFIED","RESOLVED","SYSTEM","unknown",null])
   expect(()=>parseHistoryFilter({kind:invalid})).toThrow();
 });
 it("bounds search input length",()=>{
  expect(()=>parseHistoryFilter({search:"a".repeat(121)})).toThrow();
  expect(()=>parseHistoryFilter({search:1})).toThrow();
 });
});
describe("stable history page boundaries",()=>{
 it("returns only requested results and a continuation cursor",()=>{
  const rows=[
   item("clhistory003"),item("clhistory002"),item("clhistory001")
  ];
  const page=makeHistoryPage(rows,2);
  expect(page.rows.map(x=>x.id)).toEqual(["clhistory003","clhistory002"]);
  expect(page.hasMore).toBe(true);
  expect(page.nextCursor).toBe("2026-10-31T12:00:00.000Z|clhistory002");
 });
 it("finishes without a cursor on the last page",()=>{
  const page=makeHistoryPage([item("clhistory001")],25);
  expect(page.hasMore).toBe(false);
  expect(page.nextCursor).toBeNull();
 });
 it("returns an empty page instead of inventing events",()=>{
  expect(makeHistoryPage([],25)).toEqual({
   rows:[],hasMore:false,nextCursor:null,returned:0
  });
 });
 it("counts event categories and nonattributed authors",()=>{
  const rows=[item("clhistory001","CREATED"),item("clhistory002","COMMENTED"),
   item("clhistory003","REOPENED"),{...item("clhistory004"),actorUserId:null}];
  expect(histogramHistory(rows)).toMatchObject({
   created:1,updated:1,commented:1,reopened:1,anonymous:1
  });
 });
 it("groups UTC days deterministically",()=>{
  const days=activityDayBuckets([
   item("clhistory001","UPDATED",new Date("2026-10-29T23:59:59Z")),
   item("clhistory002","UPDATED",new Date("2026-10-30T00:00:00Z")),
   item("clhistory003","UPDATED",new Date("2026-10-30T12:00:00Z"))
  ]);
  expect(days).toEqual([{date:"2026-10-29",count:1},{date:"2026-10-30",count:2}]);
 });
 it("attributes activity to actors without manufacturing identity",()=>{
  const groups=activityByActor([
   item("clhistory001","COMMENTED"),item("clhistory002","UPDATED"),
   {...item("clhistory003","UPDATED"),actorUserId:null}
  ]);
  expect(groups).toEqual([
   {actorUserId:"actor12345",total:2,comments:1,updates:1},
   {actorUserId:"DELETED_MEMBER",total:1,comments:0,updates:1}
  ]);
 });
});
describe("CSV preservation and spreadsheet safety",()=>{
 it("preserves separate immutable audit fields",()=>{
  expect(AUDIT_COLUMNS).toHaveLength(9);
  expect(AUDIT_COLUMNS).toContain("Before JSON");
  expect(AUDIT_COLUMNS).toContain("After JSON");
  expect(AUDIT_COLUMNS).not.toContain("Verified security");
 });
 it("neutralizes spreadsheet formulas even with whitespace prefixes",()=>{
  for(const string of ["=2+3","-5","+SUM(A1)","@LOOKUP(1)","  =1"]){
   expect(auditExportCell(string)).toBe(`"'${string}"`);
  }
 });
 it("quotes data with commas, double-quotes and line breaks",()=>{
  expect(auditExportCell('one,"two"\nthree')).toBe('"one,""two""\nthree"');
 });
 it("serializes actual event snapshots without verification inference",()=>{
  const csv=serializeAuditHistory([{
   ...item("clhistory001"),
   actor:{name:"Analyst",email:"analyst@example.org"},
   before:{status:"TODO"},after:{status:"DONE"}
  }]);
  expect(csv).toContain("clhistory001");
  expect(csv).toContain('"{""status"":""TODO""}"');
  expect(csv).toContain('"{""status"":""DONE""}"');
  expect(csv).toContain("Analyst");
 });
 it("exports headers alone when no history exists",()=>{
  const csv=serializeAuditHistory([]);
  expect(csv.split("\r\n")).toHaveLength(2);
 });
 it("does not manufacture actors for deleted users",()=>{
  const csv=serializeAuditHistory([{
   ...item("clhistory001"),actorUserId:null,actor:null,before:null,after:null
  }]);
  expect(csv).not.toContain('"COMMENTED"');
  expect(csv).toContain('"UPDATED"');
  expect(csv).toContain('"clhistory001"');
 });
});
