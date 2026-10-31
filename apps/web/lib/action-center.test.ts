import {describe,expect,it} from "vitest";
import {exportActionCenterCsv,filterActionCenterRecords,parseActionCenterView,summarizeActionCenterRecords} from "./action-center";
const action=(id:string,status:string,needsVerification=false)=>({
 id,title:"Action "+id,status,severity:"HIGH",findingStatus:"OPEN",needsVerification,
});
const items=[
 action("proposed","PROPOSED"),action("active","EXECUTING"),
 action("review","SUCCEEDED",true),action("done","VERIFIED"),
 action("failed","FAILED"),action("approved","APPROVED"),
];
describe("SME action center",()=>{
 it("defaults to the attention view for unrecognized requests",()=>{
  expect(parseActionCenterView("untrusted")).toBe("attention");
  expect(parseActionCenterView("verified")).toBe("verified");
  expect(parseActionCenterView(undefined)).toBe("attention");
 });
 it("filters actions by actual workflow state rather than claims of improvement",()=>{
  expect(filterActionCenterRecords(items,"attention").map(x=>x.id)).toEqual(["proposed","review","failed","approved"]);
  expect(filterActionCenterRecords(items,"active").map(x=>x.id)).toEqual(["active"]);
  expect(filterActionCenterRecords(items,"verified").map(x=>x.id)).toEqual(["done"]);
  expect(filterActionCenterRecords(items,"all")).toHaveLength(6);
 });
 it("reports distinct totals without counting acknowledgments as verified",()=>{
  expect(summarizeActionCenterRecords(items)).toEqual({
   total:6,inProgress:1,needsVerification:1,verified:1,needsAttention:4,
  });
 });
 it("exports spreadsheet-safe text without corrupting delimiters",()=>{
  const content=exportActionCenterCsv([{
   ...action("id","PROPOSED"),title:'=HYPERLINK("x,y")',
  }],"org")!;
  expect(content).toContain('"\'=HYPERLINK(""x,y"")"');
  expect(content).toContain('"PROPOSED"');
  expect(content).toContain('"NO"');
  expect(content.startsWith("\uFEFFactionId,title,status")).toBe(true);
 });
 it("refuses invalid export requests and does not mutate source",()=>{
  const prior=JSON.stringify(items);
  expect(exportActionCenterCsv(items,"")).toBeNull();
  expect(exportActionCenterCsv([{...action("","PROPOSED")}],"org")).toBeNull();
  exportActionCenterCsv(items,"org");
  expect(JSON.stringify(items)).toBe(prior);
 });
});