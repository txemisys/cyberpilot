import { describe, expect, it } from "vitest";
import { admittedJob, admissionEvent, applyJobCommand,
  type OfflineJobSnapshot } from "./durable-offline-job-domain";
import { buildQueueDispatchPlan, classifyQueueFailure,
  reviewDeadLetters, analyzeJobEventChain,
  validateQueueDispatchPolicy, DEFAULT_QUEUE_DISPATCH_POLICY }
  from "./offline-job-dispatch-assurance";
import { evaluateQueueFaultScenarios, planQueueRecovery }
  from "./offline-job-recovery-fault-matrix";
import { buildQueueAssuranceReport, exportQueueAssuranceReport,
  compareQueueAssuranceReports } from "./offline-job-assurance-report";
const now="2026-11-23T10:00:00.000Z",then="2026-11-23T10:00:30.000Z";
function sample(id="job-1234567"):OfflineJobSnapshot{
  return admittedJob({organizationId:"tenant-1234",requestedById:"admin-1234",
    idempotencyKey:"key-"+id,type:"CAPTURE_TIMELINE_AUDIT",payload:{},
    scheduledAt:now,expiresAt:"2026-11-24T10:00:00.000Z"},id,now);
}
function claim(s:OfflineJobSnapshot) {
  const c=applyJobCommand(s,{organizationId:s.organizationId,
    jobId:s.id,actorId:"admin-1234",expectedRevision:s.revision,
    kind:"CLAIMED",leaseToken:"token-1234567",leaseSeconds:30,at:then});
  expect(c.accepted).toBe(true);return c;
}
describe("offline dispatch: explicit operator planning",()=>{
  it("respects policy, tenant scope and schedulability",()=>{
    expect(validateQueueDispatchPolicy(DEFAULT_QUEUE_DISPATCH_POLICY)).toEqual([]);
    const s=sample();
    const p=buildQueueDispatchPlan(s.organizationId,[{job:s}],then);
    expect(p.selected).toEqual([s.id]);
    expect(p.providerCalls).toBe(0);
    expect(p.dispatchPerformed).toBe(false);
    expect(buildQueueDispatchPlan(s.organizationId,[{job:s}],then,
      DEFAULT_QUEUE_DISPATCH_POLICY,true).selected).toEqual([]);
    expect(buildQueueDispatchPlan(s.organizationId,[{
      job:{...s,organizationId:"foreign-tenant"}}],then).selected).toEqual([]);
  });
  it("counts lease occupancy and excludes capacity overflow",()=>{
    const s=sample();
    const leased=[sample("job-2222222"),sample("job-3333333")].map(x=>{
      const result=claim(x);return result.next!;
    });
    const p=buildQueueDispatchPlan(s.organizationId,[{job:s},
      ...leased.map(job=>({job}))],then);
    expect(p.availableCapacity).toBe(0);
    expect(p.selectedCount).toBe(0);
  });
  it("never retries permanent failures and respects retry budget",()=>{
    const leased=claim(sample()).next!;
    expect(classifyQueueFailure(leased,"PROVIDER_DENIED","AUTHORIZATION",then)
      .kind).toBe("DEAD_LETTER");
    expect(classifyQueueFailure(leased,"TEMPORARY_ERROR","TRANSIENT",then)
      .retryAfterSeconds).toBe(15);
    expect(classifyQueueFailure({...leased,attempts:leased.maxAttempts},
      "WORKER_TIMEOUT","TIMEOUT",then).kind).toBe("DEAD_LETTER");
  });
  it("detects missing immutable event and never proves LIVE recovery",()=>{
    const s=sample(),e=admissionEvent(s);
    expect(analyzeJobEventChain(s,[e]).issues).toEqual([]);
    expect(analyzeJobEventChain(s,[]).issues).toContain("EVENT_HISTORY_INCOMPLETE");
    const fault=evaluateQueueFaultScenarios(s.organizationId,[s],
      {[s.id]:[e]},then);
    expect(fault.scenarioCount).toBe(16);
    expect(fault.customerTenantsProbed).toBe(0);
    expect(fault.sqlRestoreExecuted).toBe(false);
    expect(fault.detectedCount).toBeGreaterThan(12);
  });
  it("preserves exhausted dead-letter as manual review",()=>{
    const s={...sample(),status:"DEAD_LETTER" as const,
      attempts:4, lastFailure:"UNRECOVERABLE",failureClass:"PERMANENT" as const};
    expect(reviewDeadLetters(s.organizationId,[s],then).outstanding).toBe(1);
    expect(planQueueRecovery(s,then).automaticReplayAllowed).toBe(false);
  });
});
describe("queue assurance report",()=>{
  it("builds complete evidence and bounded export",()=>{
    const s=sample();
    const r=buildQueueAssuranceReport({organizationId:s.organizationId,
      snapshots:[s],histories:{[s.id]:[admissionEvent(s)]},
      at:then,truncated:false});
    expect(r.acceptance).toBe("READY_FOR_OPERATOR_REVIEW");
    expect(r.cleanAuditRecords).toBe(1);
    expect(r.provenProviderWrites).toBe(0);
    for(const f of ["JSON","CSV","MARKDOWN"] as const){
      const a=exportQueueAssuranceReport(r,f);
      expect(a.content.length).toBeGreaterThan(0);
      expect(a.digest).toMatch(/^[a-f0-9]{64}$/);
    }
  });
  it("recognizes broken histories and avoids overstating full coverage",()=>{
    const s=sample();
    const broken=buildQueueAssuranceReport({
      organizationId:s.organizationId,snapshots:[s],histories:{},
      at:then,truncated:true});
    expect(broken.acceptance).toBe("INCOMPLETE");
    expect(broken.incompleteAuditRecords).toBe(1);
    const later=buildQueueAssuranceReport({
      organizationId:s.organizationId,snapshots:[s],
      histories:{[s.id]:[admissionEvent(s)]},
      at:"2026-11-23T11:00:00.000Z",truncated:false});
    expect(compareQueueAssuranceReports(broken,later).comparable).toBe(false);
  });
});
