import {describe,expect,it} from "vitest";
import {buildWorkCsv,exportFileName,WORK_EXPORT_COLUMNS,workExportValues,type WorkExportRow} from "./remediation-work-export";
const record:WorkExportRow={
  id:"clwork1234",title:"Review conditional access",
  description:"Coordinate change window and review evidence",
  status:"IN_PROGRESS",priority:"HIGH",
  assignee:{name:"Team member",email:"team@example.org"},
  dueAt:new Date("2026-11-05T12:00:00Z"),dueState:"SOON",
  remediation:{title:"Require stronger authentication",status:"APPROVED"},
  finding:{title:"MFA not enforced",severity:"HIGH",status:"OPEN"},
  createdAt:new Date("2026-10-10T08:00:00Z"),
  updatedAt:new Date("2026-10-31T08:00:00Z"),
  completedAt:null,revision:3
};
describe("operational CSV export",()=>{
  it("preserves a stable, reviewable header schema",()=>{
    expect(WORK_EXPORT_COLUMNS).toHaveLength(18);
    expect(WORK_EXPORT_COLUMNS).toContain("Work status");
    expect(WORK_EXPORT_COLUMNS).toContain("Remediation status");
    expect(WORK_EXPORT_COLUMNS).toContain("Finding status");
    expect(WORK_EXPORT_COLUMNS).not.toContain("Verified");
  });
  it("serializes expected fields and ISO timestamps",()=>{
    const values=workExportValues(record);
    expect(values).toHaveLength(18);
    expect(values[0]).toBe(record.id);
    expect(values[3]).toBe("IN_PROGRESS");
    expect(values[6]).toBe("team@example.org");
    expect(values[7]).toBe("2026-11-05T12:00:00.000Z");
    expect(values[13]).toBe("OPEN");
    expect(values[16]).toBe("");
    expect(values[17]).toBe(3);
  });
  it("escapes commas, quotes, and multiline values",()=>{
    const csv=buildWorkCsv([{...record,title:'Read "policy", recheck',description:"First\nSecond"}]);
    expect(csv).toContain('"Read ""policy"", recheck"');
    expect(csv).toContain('"First\nSecond"');
    expect(csv.endsWith("\r\n")).toBe(true);
  });
  it("neutralizes formula injection including prefixed whitespace",()=>{
    for(const value of ["=1+1","+SUM(A1:A3)","-4*4","@SUM(1)","   =HYPERLINK(1)","\t+RUN(1)"]){
      const csv=buildWorkCsv([{...record,title:value}]);
      expect(csv).toContain(`"'${value}"`);
    }
  });
  it("does not prefix ordinary text or valid values",()=>{
    const csv=buildWorkCsv([record]);
    expect(csv).toContain('"Review conditional access"');
    expect(csv).toContain('"HIGH"');
    expect(csv).toContain('"3"');
  });
  it("handles absent assignees and target dates safely",()=>{
    const csv=buildWorkCsv([{...record,assignee:null,dueAt:null}]);
    expect(csv).toContain(',"","","","SOON",');
  });
  it("includes header for empty exports",()=>{
    const csv=buildWorkCsv([]);
    expect(csv.split("\r\n")).toHaveLength(2);
    expect(csv).toContain('"Coordination priority"');
  });
  it("sanitizes filenames and retains calendar dates",()=>{
    const at=new Date("2026-10-31T12:00:00Z");
    expect(exportFileName("north-office",at)).toBe("cyberpilot-work-north-office-2026-10-31.csv");
    expect(exportFileName("bad/../name",at)).not.toContain("/");
  });
});
