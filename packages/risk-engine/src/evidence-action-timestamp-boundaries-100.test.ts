import { describe, expect, it } from "vitest";
import { buildActionPlan } from "./evidence-action-plan";
import { applyActionProgress } from "./evidence-action-progress";
import type { EvidenceAction } from "./evidence-actions";
import type { ActionProgressEvent } from "./evidence-action-progress";

// Calendar, leap-year, clock, UTC and lexical boundary regression matrix.
// One independently executed test per input: 50 valid and 50 invalid samples.
const valid = [
  "2024-02-29T00:00:00Z",
  "2000-02-29T23:59:59Z",
  "2028-02-29T12:30:59Z",
  "2032-02-29T01:02:03Z",
  "2036-02-29T09:08:07Z",
  "2040-02-29T10:10:10Z",
  "2044-02-29T11:11:11Z",
  "2048-02-29T12:12:12Z",
  "2052-02-29T13:13:13Z",
  "2056-02-29T14:14:14Z",
  "2026-01-31T00:00:00Z",
  "2026-03-31T01:01:01Z",
  "2026-05-31T02:02:02Z",
  "2026-07-31T03:03:03Z",
  "2026-08-31T04:04:04Z",
  "2026-10-31T05:05:05Z",
  "2026-12-31T06:06:06Z",
  "2026-04-30T07:07:07Z",
  "2026-06-30T08:08:08Z",
  "2026-09-30T09:09:09Z",
  "2026-11-30T10:10:10Z",
  "2026-02-28T11:11:11Z",
  "2025-02-28T12:12:12Z",
  "2100-02-28T13:13:13Z",
  "2400-02-29T14:14:14Z",
  "2026-10-29T00:00:00.001Z",
  "2026-10-29T00:00:00.010Z",
  "2026-10-29T00:00:00.100Z",
  "2026-10-29T00:00:00.999Z",
  "2026-10-29T23:59:59.999Z",
  "2026-10-29T12:00:00.001Z",
  "2026-10-29T12:00:00.099Z",
  "2026-10-29T12:00:00.900Z",
  "2026-10-29T12:34:56.123Z",
  "2026-10-29T12:34:56.789Z",
  "2026-10-29T00:01:00Z",
  "2026-10-29T01:00:00Z",
  "2026-10-29T02:03:04Z",
  "2026-10-29T06:07:08Z",
  "2026-10-29T09:10:11Z",
  "2026-10-29T11:12:13Z",
  "2026-10-29T13:14:15Z",
  "2026-10-29T15:16:17Z",
  "2026-10-29T17:18:19Z",
  "2026-10-29T19:20:21Z",
  "2026-10-29T21:22:23Z",
  "2026-10-29T22:23:24Z",
  "2026-10-29T23:24:25Z",
  "2026-10-29T23:59:58Z",
  "2026-10-29T23:59:59Z"
] as const;
const invalid = [
  "2026-02-29T00:00:00Z",
  "2025-02-29T00:00:00Z",
  "2100-02-29T00:00:00Z",
  "1900-02-29T00:00:00Z",
  "2026-02-30T00:00:00Z",
  "2026-02-31T00:00:00Z",
  "2026-04-31T00:00:00Z",
  "2026-06-31T00:00:00Z",
  "2026-09-31T00:00:00Z",
  "2026-11-31T00:00:00Z",
  "2026-01-32T00:00:00Z",
  "2026-03-32T00:00:00Z",
  "2026-05-32T00:00:00Z",
  "2026-07-32T00:00:00Z",
  "2026-08-32T00:00:00Z",
  "2026-10-32T00:00:00Z",
  "2026-12-32T00:00:00Z",
  "2026-00-01T00:00:00Z",
  "2026-13-01T00:00:00Z",
  "2026-10-00T00:00:00Z",
  "2026-10-29T24:00:00Z",
  "2026-10-29T25:00:00Z",
  "2026-10-29T99:00:00Z",
  "2026-10-29T12:60:00Z",
  "2026-10-29T12:99:00Z",
  "2026-10-29T12:30:60Z",
  "2026-10-29T12:30:99Z",
  "2026-10-29T-1:00:00Z",
  "2026-10-29T12:-1:00Z",
  "2026-10-29T12:30:-1Z",
  "2026-10-29T00:00:00+00:00",
  "2026-10-29T00:00:00-00:00",
  "2026-10-29T01:00:00+01:00",
  "2026-10-29T00:00:00+14:00",
  "2026-10-29T00:00:00",
  "2026-10-29T00:00Z",
  "2026-10-29",
  "2026/10/29T00:00:00Z",
  "2026-10-29 00:00:00Z",
  "2026-10-29t00:00:00z",
  " 2026-10-29T00:00:00Z",
  "2026-10-29T00:00:00Z ",
  "2026-10-29T00:00:00.Z",
  "2026-10-29T00:00:00. Z",
  "2026-10-29T00:00:00,123Z",
  "2026-10-29T00:00:00.123+00:00",
  "2026-10-29T00:00:00UTC",
  "2026-10-29T00:00:00ZZ",
  "not-a-date",
  ""
] as const;
const action: EvidenceAction = { id:"boundary",domain:"WEB",controlId:"boundary",source:"DOMAIN",scope:"example",priority:"HIGH",reason:"ERROR",state:"PROPOSED",verifiedRisk:false };
const plan = () => buildActionPlan("org-boundary",[action])!;
const event = (at:string): ActionProgressEvent => ({organizationId:"org-boundary",actionId:"boundary",status:"IN_PROGRESS",at});

describe("100 UTC progress timestamp calendar and format boundary cases", () => {
  valid.forEach((timestamp,index) => {
    it(`valid #${index+1}: ${timestamp}`,() => {
      const result=applyActionProgress(plan(),[event(timestamp)],"2026-10-30");
      expect(result.applied).toBe(1);
      expect(result.rejected).toEqual([]);
      expect(result.plan.summary.inProgress).toBe(1);
    });
  });
  invalid.forEach((timestamp,index) => {
    it(`invalid #${index+51}: ${JSON.stringify(timestamp)}`,() => {
      const result=applyActionProgress(plan(),[event(timestamp)],"2026-10-30");
      expect(result.applied).toBe(0);
      expect(result.rejected).toEqual([{index:0,reason:"INVALID_TIME"}]);
      expect(result.plan.summary.todo).toBe(1);
    });
  });
});
