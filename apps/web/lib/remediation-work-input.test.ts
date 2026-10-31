import {describe,expect,it} from "vitest";
import {
  canCommentWork,canManageWork,canReadWork,deriveWorkDue,
  parseAssignee,parsePriority,parseRevision,parseStatus,
  parseWorkComment,parseWorkCreate,parseWorkDescription,parseWorkDueAt,
  parseWorkFilter,parseWorkId,parseWorkMutation,parseWorkPatch,
  parseWorkTitle,transitionWorkStatus,workSummary,WorkInputError
} from "./remediation-work-input";
const validId="cl5example1234";
const validCreate={
  remediationId:validId,title:"Review MFA settings",description:"Collect change record",
  status:"TODO",priority:"HIGH",assigneeUserId:null,dueAt:"2026-12-01"
};
describe("operational work RBAC",()=>{
  it("allows every organization member to read tracked work",()=>{
    for(const role of ["OWNER","ADMIN","MEMBER","AUDITOR"] as const)
      expect(canReadWork(role)).toBe(true);
  });
  it("reserves assignment and status changes for organization management",()=>{
    expect(canManageWork("OWNER")).toBe(true);
    expect(canManageWork("ADMIN")).toBe(true);
    expect(canManageWork("MEMBER")).toBe(false);
    expect(canManageWork("AUDITOR")).toBe(false);
  });
  it("allows members to record progress but keeps auditors read-only",()=>{
    expect(canCommentWork("OWNER")).toBe(true);
    expect(canCommentWork("ADMIN")).toBe(true);
    expect(canCommentWork("MEMBER")).toBe(true);
    expect(canCommentWork("AUDITOR")).toBe(false);
  });
});
describe("creation validation and normalization",()=>{
  it("parses a fully specified task without changing the input",()=>{
    const before=JSON.stringify(validCreate);
    const parsed=parseWorkCreate(validCreate);
    expect(parsed).toMatchObject({
      remediationId:validId,title:"Review MFA settings",
      priority:"HIGH",status:"TODO",assigneeUserId:null
    });
    expect(parsed.dueAt?.toISOString()).toBe("2026-12-01T12:00:00.000Z");
    expect(JSON.stringify(validCreate)).toBe(before);
  });
  it("uses conservative defaults for optional fields",()=>{
    const item=parseWorkCreate({remediationId:validId,title:"  Check MFA  "});
    expect(item).toMatchObject({
      title:"Check MFA",description:"",status:"TODO",priority:"NORMAL",
      dueAt:null,assigneeUserId:null
    });
  });
  it("rejects absent or wrong remediation identifiers",()=>{
    for(const invalid of ["",0,null,{},true,"!","abc","a".repeat(101)])
      expect(()=>parseWorkCreate({...validCreate,remediationId:invalid})).toThrow(WorkInputError);
  });
  it("rejects unexpected create keys",()=>{
    expect(()=>parseWorkCreate({...validCreate,organizationId:"another-tenant"})).toThrow(/Unknown/);
    expect(()=>parseWorkCreate({...validCreate,verifiedAt:new Date()})).toThrow(/Unknown/);
    expect(()=>parseWorkCreate({...validCreate,status:"VERIFIED"})).toThrow();
  });
  it("trims titles and enforces length and control characters",()=>{
    expect(parseWorkTitle("  Fixed issue  ")).toBe("Fixed issue");
    for(const value of [null,123,"", "hi", "a".repeat(161), "Hi\u0000there"])
      expect(()=>parseWorkTitle(value)).toThrow(WorkInputError);
  });
  it("accepts bounded multiline descriptions",()=>{
    expect(parseWorkDescription("  First\nSecond  ")).toBe("First\nSecond");
    expect(parseWorkDescription("")).toBe("");
    expect(()=>parseWorkDescription("z".repeat(4001))).toThrow();
    expect(()=>parseWorkDescription("broken\u0001text")).toThrow();
  });
  it("requires meaningful progress comments",()=>{
    expect(parseWorkComment("  Ticket #123 checked  ")).toBe("Ticket #123 checked");
    for(const value of ["","  ","x".repeat(2001),{},undefined,"bad\u0000text"])
      expect(()=>parseWorkComment(value)).toThrow();
  });
  it("rejects invalid due date calendar values and formats",()=>{
    for(const value of ["2026-02-30","2026-13-01","tomorrow","2026-2-1","1999-12-01","2101-01-01",42])
      expect(()=>parseWorkDueAt(value)).toThrow(WorkInputError);
    expect(parseWorkDueAt("2028-02-29")?.toISOString()).toContain("2028-02-29");
    expect(parseWorkDueAt(null)).toBeNull();
    expect(parseWorkDueAt("")).toBeNull();
  });
  it("rejects unapproved work states and priorities",()=>{
    for(const value of ["VERIFIED","RESOLVED","SUCCEEDED","FAILED","OPEN",0])
      expect(()=>parseStatus(value)).toThrow();
    for(const value of ["CRITICAL","NONE","AUTO",null])
      expect(()=>parsePriority(value)).toThrow();
  });
  it("normalizes empty assignees and rejects arbitrary inputs",()=>{
    expect(parseAssignee("")).toBeNull();
    expect(parseAssignee(undefined)).toBeNull();
    expect(parseAssignee(null)).toBeNull();
    expect(parseAssignee(validId)).toBe(validId);
    expect(()=>parseAssignee("x")).toThrow();
  });
});
describe("work patch and concurrency",()=>{
  it("only updates fields explicitly included",()=>{
    expect(parseWorkPatch({title:"  Updated action  "})).toEqual({title:"Updated action"});
    expect(parseWorkPatch({dueAt:null,status:"BLOCKED"})).toEqual({dueAt:null,status:"BLOCKED"});
  });
  it("rejects empty updates and server-owned fields",()=>{
    expect(()=>parseWorkPatch({})).toThrow();
    expect(()=>parseWorkPatch({revision:17})).toThrow();
    expect(()=>parseWorkPatch({organizationId:"other"})).toThrow();
    expect(()=>parseWorkPatch({completedAt:"2026-01-01"})).toThrow();
    expect(()=>parseWorkPatch({verifiedAt:"2026-01-01"})).toThrow();
  });
  it("rejects revisions that cannot be used for optimistic locking",()=>{
    for(const revision of [0,-1,1.5,"1",null,2147483648])
      expect(()=>parseRevision(revision)).toThrow();
    expect(parseRevision(1)).toBe(1);
    expect(parseRevision(2147483647)).toBe(2147483647);
  });
  it("parses each supported mutation",()=>{
    expect(parseWorkMutation({kind:"create",value:validCreate}).kind).toBe("create");
    expect(parseWorkMutation({kind:"update",id:validId,revision:3,value:{status:"DONE"}}).kind).toBe("update");
    expect(parseWorkMutation({kind:"comment",id:validId,comment:"Reviewed"}).kind).toBe("comment");
  });
  it("rejects attempts to mutate work state via a comment",()=>{
    expect(()=>parseWorkMutation({kind:"comment",id:validId,comment:"OK",status:"DONE"})).toThrow();
    expect(()=>parseWorkMutation({kind:"delete",id:validId})).toThrow();
    expect(()=>parseWorkMutation([])).toThrow();
    expect(()=>parseWorkMutation({kind:"update",id:validId,revision:1,value:{status:"VERIFIED"}})).toThrow();
  });
  it("requires cancelled work to be explicitly reopened",()=>{
    expect(()=>transitionWorkStatus("CANCELLED","DONE")).toThrow();
    expect(()=>transitionWorkStatus("CANCELLED","IN_PROGRESS")).toThrow();
    expect(transitionWorkStatus("CANCELLED","TODO")).toBe("UPDATE");
    expect(transitionWorkStatus("DONE","IN_PROGRESS")).toBe("REOPEN");
    expect(transitionWorkStatus("DONE","BLOCKED")).toBe("REOPEN");
    expect(transitionWorkStatus("DONE","TODO")).toBe("REOPEN");
  });
});
describe("filter boundaries",()=>{
  it("defaults to first page and no filter",()=>{
    expect(parseWorkFilter({})).toMatchObject({
      status:"ALL",priority:"ALL",assigneeUserId:"ALL",
      due:"ALL",search:"",page:1,pageSize:20
    });
  });
  it("applies accepted filters independently",()=>{
    expect(parseWorkFilter({
      status:"BLOCKED",priority:"URGENT",assignee:"UNASSIGNED",
      due:"OVERDUE",search:"  MFA ",page:"3",pageSize:"50"
    })).toMatchObject({
      status:"BLOCKED",priority:"URGENT",assigneeUserId:"UNASSIGNED",
      due:"OVERDUE",search:"MFA",page:3,pageSize:50
    });
  });
  it("limits abusive page, search and page size inputs",()=>{
    const result=parseWorkFilter({
      page:"999999999",pageSize:"9999",search:"q".repeat(1000),
      status:"VERIFIED",priority:"CRITICAL",due:"HISTORICAL"
    });
    expect(result.page).toBe(1);
    expect(result.pageSize).toBe(20);
    expect(result.search).toHaveLength(120);
    expect(result.status).toBe("ALL");
    expect(result.priority).toBe("ALL");
    expect(result.due).toBe("ALL");
  });
});
describe("date assessment is separate from verified security",()=>{
  const now=new Date("2026-11-01T12:00:00.000Z");
  it("detects overdue and soon dates for active work",()=>{
    expect(deriveWorkDue(now,new Date("2026-10-31"),"TODO")).toBe("OVERDUE");
    expect(deriveWorkDue(now,new Date("2026-11-03"),"IN_PROGRESS")).toBe("SOON");
    expect(deriveWorkDue(now,new Date("2026-12-03"),"BLOCKED")).toBe("ON_TRACK");
  });
  it("does not call completed/cancelled work overdue",()=>{
    expect(deriveWorkDue(now,new Date("2025-01-01"),"DONE")).toBe("CLOSED");
    expect(deriveWorkDue(now,new Date("2025-01-01"),"CANCELLED")).toBe("CLOSED");
    expect(deriveWorkDue(now,null,"TODO")).toBe("NONE");
  });
  it("summarizes human work without inferring controls are verified",()=>{
    const rows=[
      {status:"TODO" as const,dueAt:new Date("2026-10-01")},
      {status:"BLOCKED" as const,dueAt:new Date("2026-11-03")},
      {status:"IN_PROGRESS" as const,dueAt:null},
      {status:"DONE" as const,dueAt:new Date("2025-01-01")},
      {status:"CANCELLED" as const,dueAt:null}
    ];
    expect(workSummary(rows,now)).toEqual({
      total:5,todo:1,working:1,blocked:1,done:1,cancelled:1,
      overdue:1,dueSoon:1
    });
  });
});
