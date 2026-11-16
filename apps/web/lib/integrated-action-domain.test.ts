import {describe,expect,it} from "vitest";
import {
  applyIntegratedActionCommand,auditIntegratedActionHistory,
  summarizeIntegratedActionBoard,compareIntegratedActionBoards,
  serializeActionBoard,digestIntegratedActionSnapshot,
  type ActionSnapshot,type ActionDomainEvent,
  type ActionCommand,
} from "./integrated-action-domain";
const start="2026-11-16T09:00:00.000Z";
const later="2026-11-16T10:00:00.000Z";
function snapshot():ActionSnapshot{
  return{
    organizationId:"org-test",actionId:"action-one",
    riskKey:"a".repeat(64),title:"Backup is unverified",
    description:"Customer declaration requires review",
    severity:"HIGH",sourceFingerprint:"b".repeat(64),
    evidenceRefs:["evidence-one"],
    status:"OPEN",priority:"HIGH",ownerUserId:null,
    dueAt:null,rationale:null,
    exceptionReason:null,exceptionExpiresAt:null,
    revision:1,createdById:"actor-owner",updatedById:"actor-owner",
    updatedAt:start,
    independentRemediationVerified:false,
    customerLegalAcceptanceProven:false,
    sourceEvidenceReevaluated:false,
  };
}
function command(kind:ActionCommand["kind"],
  props:Partial<ActionCommand>={}):ActionCommand{
  return{
    organizationId:"org-test",actionId:"action-one",
    actorUserId:"actor-owner",expectedRevision:1,
    kind,at:later,...props,
  };
}
function eventFor(action:ActionSnapshot):ActionDomainEvent{
  return{
    organizationId:action.organizationId,actionId:action.actionId,
    revision:action.revision,kind:"CREATE",
    previousStatus:"OPEN",nextStatus:action.status,
    actorUserId:action.updatedById,occurredAt:action.updatedAt,
    snapshotDigest:digestIntegratedActionSnapshot(action),
    automaticallyExecutedRemediation:false,
  };
}
describe("durable provider-neutral action workflow",()=>{
  it("supports CAS and owner assignment without performing remediation",()=>{
    const before=snapshot();
    const outcome=applyIntegratedActionCommand(before,
      command("ASSIGN",{nextOwnerUserId:"member-one"}));
    expect(outcome.accepted).toBe(true);
    expect(outcome.next?.ownerUserId).toBe("member-one");
    expect(outcome.next?.revision).toBe(2);
    expect(outcome.next?.independentRemediationVerified).toBe(false);
    expect(outcome.event?.automaticallyExecutedRemediation).toBe(false);
  });
  it("rejects stale optimistic revisions",()=>{
    const outcome=applyIntegratedActionCommand(snapshot(),
      command("START",{expectedRevision:2}));
    expect(outcome.accepted).toBe(false);
    expect(outcome.code).toBe("CAS_REVISION_CONFLICT");
  });
  it("rejects cross-tenant command",()=>{
    const outcome=applyIntegratedActionCommand(snapshot(),
      command("START",{organizationId:"org-foreign"}));
    expect(outcome.code).toBe("CROSS_TENANT_OR_ACTOR_INVALID");
  });
  it("rejects report-done without a responsible member",()=>{
    const first=applyIntegratedActionCommand(snapshot(),command("START"));
    expect(first.accepted).toBe(true);
    const next=first.next!;
    const attempt=applyIntegratedActionCommand(next,{
      ...command("REPORT_DONE"),expectedRevision:2,
      at:"2026-11-16T11:00:00.000Z",
      reason:"Work was reportedly completed by operator",
    });
    expect(attempt.code).toBe("OWNER_REQUIRED_TO_REPORT_COMPLETION");
  });
  it("rejects completed reports without substantive rationale",()=>{
    const before=snapshot();
    before.status="IN_PROGRESS";
    before.ownerUserId="member-one";
    const attempt=applyIntegratedActionCommand(before,
      command("REPORT_DONE",{reason:"done"}));
    expect(attempt.code).toBe("REASON_MINIMUM_NOT_MET");
  });
  it("does not grant legally approved risk acceptance for exception",()=>{
    const outcome=applyIntegratedActionCommand(snapshot(),
      command("ACCEPT_EXCEPTION",{
        reason:"Temporary control exception with mitigation",
        exceptionExpiresAt:"2026-11-18T10:00:00.000Z",
      }));
    expect(outcome.accepted).toBe(true);
    expect(outcome.next?.status).toBe("EXCEPTION");
    expect(outcome.next?.customerLegalAcceptanceProven).toBe(false);
  });
  it("rejects indefinite and overly long exceptions",()=>{
    const noExpiry=applyIntegratedActionCommand(snapshot(),
      command("ACCEPT_EXCEPTION",{
        reason:"Temporary control exception with mitigation",
      }));
    expect(noExpiry.code).toBe("EXCEPTION_DURATION_INVALID");
    const tooLong=applyIntegratedActionCommand(snapshot(),
      command("ACCEPT_EXCEPTION",{
        reason:"Temporary control exception with mitigation",
        exceptionExpiresAt:"2027-12-01T10:00:00.000Z",
      }));
    expect(tooLong.code).toBe("EXCEPTION_DURATION_INVALID");
  });
  it("rejects expiry transition before actual expiry",()=>{
    const action=snapshot();
    action.status="EXCEPTION";
    action.exceptionReason="Temporary control exception with mitigation";
    action.exceptionExpiresAt="2026-11-20T10:00:00.000Z";
    expect(applyIntegratedActionCommand(action,
      command("EXPIRE_EXCEPTION")).code).toBe("EXCEPTION_NOT_EXPIRED");
  });
  it("rejects unsupported workflow jumps",()=>{
    expect(applyIntegratedActionCommand(snapshot(),
      command("REPORT_DONE",{
        reason:"Actual operator work was completed",
      })).code).toBe("ILLEGAL_WORKFLOW_TRANSITION");
  });
  it("counts reported results as unverified",()=>{
    const done=snapshot();
    done.status="DONE_REPORTED";done.ownerUserId="member-one";
    const exception=snapshot();
    exception.actionId="action-two";
    exception.riskKey="c".repeat(64);
    exception.status="EXCEPTION";
    exception.exceptionReason="Temporary exception for organization backup";
    exception.exceptionExpiresAt="2026-11-15T09:00:00.000Z";
    const summary=summarizeIntegratedActionBoard(
      [done,exception],later,
    );
    expect(summary.reportedButNotVerified).toBe(1);
    expect(summary.expiredExceptions).toBe(1);
    expect(summary.riskActuallyRemediated).toBe(0);
    expect(summary.acceptedRiskLegallyConfirmed).toBe(0);
  });
  it("finds missing immutable event revisions",()=>{
    const initial=snapshot();
    initial.revision=2;
    const audit=auditIntegratedActionHistory(initial,[
      eventFor({...initial,revision:1}),
    ]);
    expect(audit.valid).toBe(false);
    expect(audit.errors).toContain("EVENT_HISTORY_INCOMPLETE");
  });
  it("verifies a canonical initial-event digest",()=>{
    const initial=snapshot();
    const audit=auditIntegratedActionHistory(initial,[
      eventFor(initial),
    ]);
    expect(audit.valid).toBe(true);
    expect(audit.externallyVerifiedRemediation).toBe(false);
  });
  it("detects altered event digests",()=>{
    const initial=snapshot();
    const event=eventFor(initial);
    event.snapshotDigest="f".repeat(64);
    expect(auditIntegratedActionHistory(initial,[event]).errors)
      .toContain("LATEST_DIGEST_MISMATCH");
  });
  it("returns a tenant-scoped action-board report with stable digest",()=>{
    const result=serializeActionBoard([snapshot()],later,"org-test");
    expect(result.organizationId).toBe("org-test");
    expect(result.customerRiskAcceptanceVerified).toBe(false);
    expect(result.liveRemediationExecuted).toBe(false);
    expect(result.summary.riskActuallyRemediated).toBe(0);
    expect(()=>serializeActionBoard([snapshot()],later,
      "org-foreign")).toThrow();
  });
  it("compares declared progress without declaring risk reduction",()=>{
    const before=snapshot();
    const after={...before,revision:2,
      ownerUserId:"member-one",status:"IN_PROGRESS" as const};
    const report=compareIntegratedActionBoards(
      [before],[after],later,
    );
    expect(report.revised).toContain("action-one");
    expect(report.remediationIndependentlyVerified).toBe(false);
    expect(report.humanRiskAcceptanceEstablished).toBe(false);
  });
});
