import { describe, expect, it } from "vitest";
import { DEFAULT_OFFLINE_JOB_POLICY, OFFLINE_JOB_TYPES,
  admittedJob, admissionEvent, applyJobCommand, auditJob,
  jobDigest, nextBackoffSeconds, validateJobPolicy, validateJobRequest,
  type OfflineJobRequest, type OfflineJobSnapshot,
  type JobCommand } from "./durable-offline-job-domain";
const at = "2026-11-23T12:00:00.000Z";
const after = "2026-11-23T12:01:00.000Z";
function request(type: typeof OFFLINE_JOB_TYPES[number] = "CAPTURE_TIMELINE_AUDIT"):
  OfflineJobRequest {
  return { organizationId: "tenant-1234", requestedById: "admin-1234",
    idempotencyKey: "audit-12345678", type, payload: { check: "read-only", sequence: 1 },
    scheduledAt: at, expiresAt: "2026-11-25T12:00:00.000Z" };
}
function sample(type?: typeof OFFLINE_JOB_TYPES[number]) {
  return admittedJob(request(type), "job-12345678", at);
}
function cmd(s: OfflineJobSnapshot, kind: JobCommand["kind"],
  extra: Partial<JobCommand> = {}) {
  return applyJobCommand(s, { kind, organizationId: s.organizationId, jobId: s.id,
    actorId: "admin-1234", expectedRevision: s.revision, at: after, ...extra });
}
describe("PostgreSQL-backed offline job state-machine contract", () => {
  it("validates deterministic canonical digests for nested shuffled JSONB keys", () => {
    const first = { b: [{ z: "foo", a: 3 }], a: { y: 9, x: true } };
    const second = { a: { x: true, y: 9 }, b: [{ a: 3, z: "foo" }] };
    expect(jobDigest(first)).toBe(jobDigest(second));
    expect(jobDigest({ ...first, b: [] })).not.toBe(jobDigest(first));
  });
  it("admits only type-bound bounded requests and stable policy", () => {
    expect(validateJobPolicy(DEFAULT_OFFLINE_JOB_POLICY)).toEqual([]);
    for (const type of OFFLINE_JOB_TYPES) {
      const s = sample(type);
      expect(s.providerWrites).toBe(0);
      expect(s.status).toBe("QUEUED");
      expect(s.attempts).toBe(0);
      expect(auditJob(s, [admissionEvent(s)]).valid).toBe(true);
    }
    expect(validateJobRequest({ ...request(), idempotencyKey: "bad" }).length)
      .toBeGreaterThan(0);
    expect(validateJobRequest({ ...request(), expiresAt: at }).length)
      .toBeGreaterThan(0);
    expect(validateJobRequest({ ...request(),
      payload: { excess: "x".repeat(20000) } }).length).toBeGreaterThan(0);
  });
  it("rejects stale revisions, tenant drift and premature claim", () => {
    const s = sample();
    expect(cmd(s, "CLAIMED", { expectedRevision: 0, leaseToken: "lease-12345678",
      leaseSeconds: 30 }).code).toBe("JOB_REVISION_CONFLICT");
    expect(cmd(s, "CLAIMED", { organizationId: "different-tenant",
      leaseToken: "lease-12345678", leaseSeconds: 30 }).code)
      .toBe("JOB_SCOPE_INVALID");
    expect(cmd(s, "SUCCEEDED", { leaseToken: "lease-12345678",
      result: { okay: true } }).accepted).toBe(false);
  });
  it("supports claim, heartbeat and successful idempotent completion", () => {
    const s = sample();
    const claimed = cmd(s, "CLAIMED", {
      leaseToken: "lease-12345678", leaseSeconds: 90 });
    expect(claimed.accepted).toBe(true);
    expect(claimed.next?.status).toBe("LEASED");
    expect(claimed.next?.attempts).toBe(1);
    const leased = claimed.next!;
    expect(cmd(leased, "SUCCEEDED", { leaseToken: "wrong-token",
      result: { checksum: "abc" } }).accepted).toBe(false);
    const heartbeat = cmd(leased, "HEARTBEAT", {
      leaseToken: "lease-12345678", leaseSeconds: 90 });
    expect(heartbeat.accepted).toBe(true);
    const finished = cmd(heartbeat.next!, "SUCCEEDED", {
      leaseToken: "lease-12345678", result: {
        proof: "captured", providerWrites: 0 } });
    expect(finished.accepted).toBe(true);
    expect(finished.next?.status).toBe("SUCCEEDED");
    expect(finished.next?.leaseToken).toBeNull();
    expect(finished.next?.resultDigest).toBe(jobDigest({
      proof: "captured", providerWrites: 0 }));
    expect(cmd(finished.next!, "CLAIMED", {
      leaseToken: "new-token-123456", leaseSeconds: 90 }).accepted).toBe(false);
  });
  it("computes bounded backoff without jitter or unbounded retries", () => {
    expect(nextBackoffSeconds(1)).toBe(15);
    expect(nextBackoffSeconds(2)).toBe(30);
    expect(nextBackoffSeconds(3)).toBe(60);
    expect(nextBackoffSeconds(8)).toBe(900);
    expect(() => nextBackoffSeconds(0)).toThrow();
  });
  it("schedules retry for transient failure and dead-letters permanent failures", () => {
    const s = cmd(sample(), "CLAIMED", {
      leaseToken: "lease-12345678", leaseSeconds: 120 }).next!;
    const retried = cmd(s, "RETRY_SCHEDULED", {
      leaseToken: "lease-12345678", failureCode: "REMOTE_READ_INTERRUPTED",
      failureClass: "TRANSIENT" });
    expect(retried.accepted).toBe(true);
    expect(retried.next?.status).toBe("RETRY_WAIT");
    expect(retried.next?.scheduledAt).toBe("2026-11-23T12:01:15.000Z");
    const afterRetry = cmd(retried.next!, "CLAIMED", {
      at: "2026-11-23T12:01:16.000Z", leaseToken: "lease-22222222",
      leaseSeconds: 120 });
    expect(afterRetry.accepted).toBe(true);
    const dead = cmd(afterRetry.next!, "DEAD_LETTERED", {
      at: "2026-11-23T12:01:20.000Z", leaseToken: "lease-22222222",
      failureCode: "INVALID_SCOPE", failureClass: "PERMANENT" });
    expect(dead.accepted).toBe(true);
    expect(dead.next?.status).toBe("DEAD_LETTER");
    expect(dead.next?.lastFailure).toBe("INVALID_SCOPE");
  });
  it("recovers stale leases but rejects early recovery and old fences", () => {
    const s = cmd(sample(), "CLAIMED", {
      leaseToken: "lease-12345678", leaseSeconds: 10 }).next!;
    expect(cmd(s, "REQUEUED").accepted).toBe(false);
    const recovered = cmd(s, "REQUEUED", {
      at: "2026-11-23T12:01:11.000Z" });
    expect(recovered.accepted).toBe(true);
    expect(recovered.next?.status).toBe("RETRY_WAIT");
    expect(cmd(recovered.next!, "SUCCEEDED", {
      leaseToken: "lease-12345678", result: {} }).accepted).toBe(false);
  });
  it("blocks cancellation of leased work and allows queued cancellation", () => {
    const s = sample();
    expect(cmd(s, "CANCELLED").next?.status).toBe("CANCELLED");
    const claimed = cmd(s, "CLAIMED", {
      leaseToken: "lease-12345678", leaseSeconds: 90 }).next!;
    expect(cmd(claimed, "CANCELLED").code).toBe("JOB_CANNOT_CANCEL");
  });
  it("detects altered event chain and lost audit entries", () => {
    const s = sample(), created = admissionEvent(s);
    const claimed = cmd(s, "CLAIMED", {
      leaseToken: "lease-12345678", leaseSeconds: 60 });
    expect(auditJob(claimed.next!, [created, claimed.event!]).valid).toBe(true);
    expect(auditJob(claimed.next!, [claimed.event!]).valid).toBe(false);
    expect(auditJob(claimed.next!, [created, { ...claimed.event!,
      digest: "bad" }]).valid).toBe(false);
  });
});
