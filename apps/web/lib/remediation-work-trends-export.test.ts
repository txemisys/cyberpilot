import {describe,it,expect} from "vitest";
import {
 parseTrendExportOptions,selectTrendEvents,trendCsv,trendIntegrity,
 EVENT_COLUMNS,DAY_COLUMNS,
} from "./remediation-work-trends-export";
import {buildWorkTrends,parseTrendFilter,type TrendEvent} from "./remediation-work-trends";
const NOW=new Date("2026-11-01T12:00:00.000Z");
const source:TrendEvent={
 id:"event_alpha",workItemId:"work_alpha",kind:"UPDATED",occurredAt:NOW,
 actorUserId:"user_alpha",before:{priority:"LOW"},after:{priority:"HIGH"},
 comment:"Updated priority",
};
const unknown:TrendEvent={...source,id:"event_unknown",kind:"UNRECOGNIZED",
 before:null,after:null,actorUserId:null};
const make=(events:TrendEvent[]=[source])=>
 buildWorkTrends(events,[],parseTrendFilter({days:7}),NOW);
describe("safe historical export parsing",()=>{
 it("provides explicit conservative defaults",()=>{
  expect(parseTrendExportOptions({})).toEqual({
   mode:"EVENTS",limit:4000,includeUnclassified:true,
  });
 });
 it.each([null,undefined,42,false,[],"invalid"])("rejects invalid object %s",value=>{
  expect(()=>parseTrendExportOptions(value)).toThrow();
 });
 it.each(["EVENTS","DAILY"])("accepts mode %s",mode=>{
  expect(parseTrendExportOptions({mode}).mode).toBe(mode);
 });
 it.each([null,"UNKNOWN",0,{}])("rejects bad mode %s",mode=>{
  expect(()=>parseTrendExportOptions({mode})).toThrow();
 });
 it.each([-1,0,4001,1.5,NaN,"300",null])("rejects bad limit %s",limit=>{
  expect(()=>parseTrendExportOptions({limit})).toThrow();
 });
 it.each([1,7,30,90,4000])("accepts bound %s",limit=>{
  expect(parseTrendExportOptions({limit}).limit).toBe(limit);
 });
 it.each([null,0,1,"false"])("rejects invalid unknown flag %s",includeUnclassified=>{
  expect(()=>parseTrendExportOptions({includeUnclassified})).toThrow();
 });
 it("rejects unrecognized export field",()=>{
  expect(()=>parseTrendExportOptions({secret:true})).toThrow();
 });
 it("supports exclusion of unknown records",()=>{
  expect(parseTrendExportOptions({includeUnclassified:false}).includeUnclassified).toBe(false);
 });
});
describe("historical export integrity and safe representation",()=>{
 it("preserves every expected CSV event field",()=>{
  const csv=trendCsv(make(),parseTrendExportOptions({}));
  for(const column of EVENT_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(column);
 });
 it("preserves every daily aggregate field",()=>{
  const csv=trendCsv(make(),parseTrendExportOptions({mode:"DAILY"}));
  for(const column of DAY_COLUMNS)
   expect(csv.split("\r\n")[0]).toContain(column);
 });
 it("exports one row for each day of a complete window",()=>{
  const csv=trendCsv(make(),parseTrendExportOptions({mode:"DAILY"}));
  expect(csv.trim().split("\r\n")).toHaveLength(8);
 });
 it("exports one event in the event format",()=>{
  const csv=trendCsv(make(),parseTrendExportOptions({}));
  expect(csv.trim().split("\r\n")).toHaveLength(2);
 });
 it("excludes explicitly unclassified records when selected",()=>{
  const selected=selectTrendEvents(make([source,unknown]),
   parseTrendExportOptions({includeUnclassified:false}));
  expect(selected).toHaveLength(1);
 });
 it("does not silently drop unknown records by default",()=>{
  const selected=selectTrendEvents(make([source,unknown]),
   parseTrendExportOptions({}));
  expect(selected).toHaveLength(2);
 });
 it("rejects incomplete history snapshots",()=>{
  const result=make();
  result.coverage.complete=false;
  expect(()=>trendCsv(result,parseTrendExportOptions({}))).toThrow();
 });
 it("rejects truncated event exports",()=>{
  const report=make([source,unknown]);
  expect(()=>trendCsv(report,parseTrendExportOptions({limit:1}))).toThrow();
 });
 it("rejects truncated daily exports",()=>{
  expect(()=>trendCsv(make(),parseTrendExportOptions({
   mode:"DAILY",limit:1,
  }))).toThrow();
 });
 it("escapes attacker-controlled spreadsheet formula prefixes",()=>{
  for(const prefix of ["=","+","-","@"]){
   const record={...source,id:"event_"+prefix,workItemId:prefix+"INJECT"};
   const csv=trendCsv(make([record]),parseTrendExportOptions({}));
   expect(csv).toContain("'"+prefix+"INJECT");
  }
 });
 it("properly quotes embedded double quotes",()=>{
  const csv=trendCsv(make([{...source,workItemId:'work_"danger"'}]),
   parseTrendExportOptions({}));
  expect(csv).toContain('work_""danger""');
 });
 it("uses CRLF in exported rows",()=>{
  expect(trendCsv(make(),parseTrendExportOptions({}))).toContain("\r\n");
 });
 it("does not export original event comments or snapshots",()=>{
  const csv=trendCsv(make([{...source,comment:"PRIVATE_COMMENT",
   before:{token:"PRIVATE_TOKEN"},after:{token:"PRIVATE_TOKEN"}}]),
   parseTrendExportOptions({}));
  expect(csv).not.toContain("PRIVATE_COMMENT");
  expect(csv).not.toContain("PRIVATE_TOKEN");
 });
 it("detects aggregate conservation of event counts",()=>{
  expect(trendIntegrity(make([source,unknown])).equalTotals).toBe(true);
 });
 it("detects mismatch rather than falsely asserting integrity",()=>{
  const report=make();
  report.summary.totalEvents+=1;
  expect(trendIntegrity(report).equalTotals).toBe(false);
 });
 it("counts unknown classifications explicitly",()=>{
  expect(trendIntegrity(make([source,unknown])).unknown).toBe(1);
 });
 it("reports an empty set with consistent totals",()=>{
  const model=trendIntegrity(make([]));
  expect(model.equalTotals).toBe(true);
  expect(model.unknown).toBe(0);
 });
 it("does not mutate the report while exporting",()=>{
  const report=make();
  const before=JSON.stringify(report);
  trendCsv(report,parseTrendExportOptions({}));
  expect(JSON.stringify(report)).toBe(before);
 });
});
