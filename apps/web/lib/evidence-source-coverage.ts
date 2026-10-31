import type {ReviewFinding} from "./finding-evidence-review";
export type EvidenceSourceSummary={
 source:"OBSERVED"|"DECLARED"|"UNKNOWN"|"ERROR";
 records:number;
 findings:number;
 withDatedObservations:number;
 withoutDatedObservations:number;
 latestAt:Date|null;
};
export type EvidenceSourceCoverage={
 findings:number;
 matchedFindings:number;
 unmatchedFindings:number;
 sourceSummaries:EvidenceSourceSummary[];
 bySeverity:{severity:string;findings:number;matched:number;unmatched:number}[];
 recordingMonths:{month:string;records:number;observed:number;declared:number;inconclusive:number}[];
};
const SOURCES=["OBSERVED","DECLARED","UNKNOWN","ERROR"] as const;
export function buildEvidenceSourceCoverage(
 findings:readonly ReviewFinding[],
):EvidenceSourceCoverage{
 const sourceSummaries:EvidenceSourceSummary[]=SOURCES.map(source=>{
  const matching=findings.filter(f=>f.evidence.some(e=>e.source===source));
  const records=matching.flatMap(f=>f.evidence.filter(e=>e.source===source));
  const dated=records.filter(e=>e.lastObservedAt instanceof Date&&
   Number.isFinite(e.lastObservedAt.getTime()));
  const latestAt=dated.length?dated.map(e=>e.lastObservedAt!)
   .reduce((a,b)=>a.getTime()>b.getTime()?a:b):null;
  return {
   source,records:records.length,findings:matching.length,
   withDatedObservations:dated.length,
   withoutDatedObservations:records.length-dated.length,
   latestAt,
  };
 });
 const severitySet=[...new Set(findings.map(f=>f.severity))];
 const severityRank:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
 const bySeverity=severitySet.map(severity=>{
  const rows=findings.filter(f=>f.severity===severity);
  const matched=rows.filter(f=>f.evidence.length>0).length;
  return {severity,findings:rows.length,matched,unmatched:rows.length-matched};
 }).sort((a,b)=>(severityRank[a.severity]??5)-(severityRank[b.severity]??5));
 const months=new Map<string,{month:string;records:number;observed:number;declared:number;inconclusive:number}>();
 for(const finding of findings){
  for(const record of finding.evidence){
   const at=record.lastObservedAt??record.capturedAt;
   if(!at||!Number.isFinite(at.getTime()))continue;
   const month=at.toISOString().slice(0,7);
   const existing=months.get(month)??{month,records:0,observed:0,declared:0,inconclusive:0};
   existing.records++;
   if(record.source==="OBSERVED")existing.observed++;
   else if(record.source==="DECLARED")existing.declared++;
   else existing.inconclusive++;
   months.set(month,existing);
  }
 }
 return {
  findings:findings.length,
  matchedFindings:findings.filter(f=>f.evidence.length>0).length,
  unmatchedFindings:findings.filter(f=>f.evidence.length===0).length,
  sourceSummaries,bySeverity,
  recordingMonths:[...months.values()].sort((a,b)=>b.month.localeCompare(a.month)).slice(0,12),
 };
}
export function exportEvidenceSourceCoverage(
 report:EvidenceSourceCoverage,
):string{
 const lines=[
  "CYBERPILOT — EVIDENCE SOURCE COVERAGE",
  "Counts are exact-identifier matches only; not a security score.",
  "Findings reviewed: "+report.findings,
  "Findings with matched evidence: "+report.matchedFindings,
  "Findings without matched evidence: "+report.unmatchedFindings,
  "",
  "EVIDENCE PROVENANCE",
  ...report.sourceSummaries.map(s=>`${s.source}: ${s.records} records across ${s.findings} findings; latest dated record: ${s.latestAt?.toISOString()??"Unknown"}`),
  "",
  "SEVERITY COVERAGE",
  ...report.bySeverity.map(s=>`${s.severity}: ${s.matched} matched, ${s.unmatched} unmatched of ${s.findings} findings`),
  "",
  "RECENT EVIDENCE RECORDING MONTHS",
  ...report.recordingMonths.map(m=>`${m.month}: ${m.records} total (${m.observed} observed, ${m.declared} declared, ${m.inconclusive} inconclusive)`),
  "",
  "A declaration is not a direct observation of a security control.",
  "Missing matches may reflect control mapping differences or absent collection.",
  "",
 ];
 return lines.join("\n");
}
