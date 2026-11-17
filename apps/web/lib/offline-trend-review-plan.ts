import type{TrendReport,TrendPair,TrendPoint}from "./offline-longitudinal-trends";
import{verifyTrendReport}from "./offline-longitudinal-trends";
export type TrendReviewRecommendation={
  id:string;organizationId:string;
  snapshotIds:string[];
  category:"MODEL_DRIFT"|"SCOPE_DRIFT"|"COVERAGE_GAP"|
  "SOURCE_PROVENANCE"|"UNSCORABLE"|"ACTION_AUDIT";
  urgency:"BLOCK"|"REVIEW"|"TRACK";
  rationale:string;nextCheck:string;
  dataComparabilityCertified:false;
  actualCustomerSecurityImproved:false;
};
export type TrendReviewPlan={
  organizationId:string;generatedAt:string;
  parentDigest:string;recommendations:TrendReviewRecommendation[];
  summary:{
    blocks:number;reviews:number;tracking:number;
    distinctSnapshots:number;
    unchangedModelAcrossAllSnapshots:boolean;
  };
  approvalRequired:true;externalCalls:0;
  certifiedRiskReduction:false;
};
function pairRecommendations(report:TrendReport,pair:TrendPair):
  TrendReviewRecommendation[]{
  const result:TrendReviewRecommendation[]=[];
  const base={organizationId:report.organizationId,
    snapshotIds:[pair.earlierId,pair.laterId],
    dataComparabilityCertified:false as const,
    actualCustomerSecurityImproved:false as const};
  const add=(category:TrendReviewRecommendation["category"],
    urgency:TrendReviewRecommendation["urgency"],
    rationale:string,nextCheck:string)=>
    result.push({...base,
      id:category+":"+pair.earlierId+":"+pair.laterId,
      category,urgency,rationale,nextCheck});
  if(["INCOMPATIBLE_MODEL","INCOMPATIBLE_REVISION"]
    .includes(pair.comparisonClass))
    add("MODEL_DRIFT","BLOCK",
      "Assessment calculation model changed between snapshots.",
      "Compare only recalculated evaluations under the same version.");
  if(pair.reasonCodes.includes("CONTROL_POPULATIONS_DIFFER"))
    add("SCOPE_DRIFT","BLOCK",
      "Expected control populations differ across snapshots.",
      "Reconcile the control catalog, scopes and applicability.");
  if(pair.comparisonClass==="INSUFFICIENT_COVERAGE")
    add("UNSCORABLE","REVIEW",
      "At least one historical evaluation has no numeric score.",
      "Investigate missing or unverifiable evidence.");
  if(pair.comparisonClass==="INCOMPATIBLE_SOURCE_CLASS")
    add("SOURCE_PROVENANCE","BLOCK",
      "Sources differ by authenticity class or sampling mode.",
      "Keep synthetic, declared and provider-derived evidence separate.");
  if(pair.comparable&&pair.coverageDelta!==null&&pair.coverageDelta<0)
    add("COVERAGE_GAP","REVIEW",
      "Recorded coverage decreased between comparable stored snapshots.",
      "Confirm whether collection scope or connector permissions changed.");
  if(pair.comparable&&pair.coverageDelta!==null&&pair.coverageDelta>0)
    add("COVERAGE_GAP","TRACK",
      "Recorded coverage increased but customer safety is not established.",
      "Inspect source authenticity and individual control evidence.");
  return result;
}
function snapshotRecommendations(report:TrendReport,
 point:TrendPoint):TrendReviewRecommendation[]{
  const results:TrendReviewRecommendation[]=[];
  if(point.score===null)results.push({
    id:"UNSCORABLE:"+point.snapshotId,organizationId:report.organizationId,
    snapshotIds:[point.snapshotId],category:"UNSCORABLE",
    urgency:"REVIEW",
    rationale:"Stored score is null and must remain undetermined.",
    nextCheck:"Review source coverage and incomplete controls.",
    dataComparabilityCertified:false,
    actualCustomerSecurityImproved:false,
  });
  if(point.sourceKind==="LIVE_LABEL")results.push({
    id:"SOURCE_PROVENANCE:"+point.snapshotId,
    organizationId:report.organizationId,snapshotIds:[point.snapshotId],
    category:"SOURCE_PROVENANCE",urgency:"REVIEW",
    rationale:"LIVE is a stored source label, not external consent verification.",
    nextCheck:"Verify real tenant consent and authenticated scope separately.",
    dataComparabilityCertified:false,
    actualCustomerSecurityImproved:false,
  });
  return results;
}
export function buildTrendReviewPlan(report:TrendReport):TrendReviewPlan{
  if(!verifyTrendReport(report).valid)
    throw Error("TREND_REVIEW_SOURCE_TAMPERED");
  const rows=[
    ...report.pairs.flatMap(x=>pairRecommendations(report,x)),
    ...report.points.flatMap(x=>snapshotRecommendations(report,x)),
  ];
  if(report.actionPulse.invalidEventChains>0)rows.push({
    id:"ACTION_AUDIT:"+report.reportDigest,
    organizationId:report.organizationId,snapshotIds:[],
    category:"ACTION_AUDIT",urgency:"BLOCK",
    rationale:"Recorded action CAS history cannot be fully reconstructed.",
    nextCheck:"Repair event sequence or mark source incomplete.",
    dataComparabilityCertified:false,actualCustomerSecurityImproved:false,
  });
  const ordered=rows.sort((a,b)=>{
    const rank={BLOCK:0,REVIEW:1,TRACK:2};
    return rank[a.urgency]-rank[b.urgency] ||
      a.id.localeCompare(b.id);
  });
  return{
    organizationId:report.organizationId,generatedAt:report.evaluatedAt,
    parentDigest:report.reportDigest,recommendations:ordered,
    summary:{
      blocks:ordered.filter(x=>x.urgency==="BLOCK").length,
      reviews:ordered.filter(x=>x.urgency==="REVIEW").length,
      tracking:ordered.filter(x=>x.urgency==="TRACK").length,
      distinctSnapshots:new Set(ordered.flatMap(x=>x.snapshotIds)).size,
      unchangedModelAcrossAllSnapshots:new Set(report.points.map(x=>
        x.modelId+"@"+x.modelRevision)).size<=1,
    },
    approvalRequired:true,externalCalls:0,
    certifiedRiskReduction:false,
  };
}
export function filterTrendReviewPlan(plan:TrendReviewPlan,input:{
  urgency?:TrendReviewRecommendation["urgency"];
  category?:TrendReviewRecommendation["category"];
  search?:string;
}={}){
  if(plan.certifiedRiskReduction!==false||plan.externalCalls!==0)
    throw Error("UNSAFE_TREND_REVIEW_PLAN");
  const search=input.search?.trim().toLowerCase()??"";
  return plan.recommendations.filter(x=>
    (!input.urgency||x.urgency===input.urgency)&&
    (!input.category||x.category===input.category)&&
    (!search||[x.id,x.rationale,x.nextCheck].join(" ")
      .toLowerCase().includes(search)));
}
