import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { db } from "@cyberpilot/database";

import {
  consumePersistentRateLimit,
  getRateLimitWindowStart,
  hashRateLimitSubject,
} from "./rate-limit";

describe("persistent rate limiting", () => {
  beforeEach(async () => {
    await db.requestRateLimit.deleteMany();
  });

  afterAll(async () => {
    await db.requestRateLimit.deleteMany();
  });

  it("hashes organization/user subjects deterministically", () => {
    expect(hashRateLimitSubject("org-1", "user-1")).toBe(
      hashRateLimitSubject("org-1", "user-1"),
    );
    expect(hashRateLimitSubject("org-1", "user-1")).not.toBe(
      hashRateLimitSubject("org-1", "user-2"),
    );
  });

  it("uses stable fixed windows", () => {
    const now = new Date("2026-10-07T08:02:34.000Z");

    expect(getRateLimitWindowStart(now, 5 * 60 * 1000).toISOString()).toBe(
      "2026-10-07T08:00:00.000Z",
    );
  });

  it("blocks requests after the limit and resets next window", async () => {
    const input = {
      scope: "test-sensitive-action",
      organizationId: "org-1",
      userId: "user-1",
      limit: 2,
      windowMs: 60_000,
    };

    const first = await consumePersistentRateLimit(
      input,
      new Date("2026-10-07T08:00:10.000Z"),
    );
    const second = await consumePersistentRateLimit(
      input,
      new Date("2026-10-07T08:00:20.000Z"),
    );
    const third = await consumePersistentRateLimit(
      input,
      new Date("2026-10-07T08:00:30.000Z"),
    );
    const nextWindow = await consumePersistentRateLimit(
      input,
      new Date("2026-10-07T08:01:00.000Z"),
    );

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(third.allowed).toBe(false);
    expect(third.retryAfterSeconds).toBe(30);
    expect(nextWindow.allowed).toBe(true);
  });
});
