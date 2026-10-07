import { createHash } from "node:crypto";

import { db } from "@cyberpilot/database";

export type PersistentRateLimitInput = {
  scope: string;
  organizationId: string;
  userId: string;
  limit: number;
  windowMs: number;
};

export type PersistentRateLimitResult = {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
};

export function hashRateLimitSubject(
  organizationId: string,
  userId: string,
): string {
  return createHash("sha256")
    .update(`${organizationId}:${userId}`)
    .digest("hex");
}

export function getRateLimitWindowStart(now: Date, windowMs: number) {
  return new Date(Math.floor(now.getTime() / windowMs) * windowMs);
}

export async function consumePersistentRateLimit(
  input: PersistentRateLimitInput,
  now = new Date(),
): Promise<PersistentRateLimitResult> {
  const subjectHash = hashRateLimitSubject(
    input.organizationId,
    input.userId,
  );
  const windowStart = getRateLimitWindowStart(now, input.windowMs);
  const expiresAt = new Date(windowStart.getTime() + input.windowMs * 2);

  const [, bucket] = await db.$transaction([
    db.requestRateLimit.deleteMany({
      where: {
        expiresAt: {
          lt: now,
        },
      },
    }),
    db.requestRateLimit.upsert({
      where: {
        scope_subjectHash_windowStart: {
          scope: input.scope,
          subjectHash,
          windowStart,
        },
      },
      create: {
        scope: input.scope,
        subjectHash,
        windowStart,
        count: 1,
        expiresAt,
      },
      update: {
        count: {
          increment: 1,
        },
        expiresAt,
      },
      select: {
        count: true,
      },
    }),
  ]);

  const windowEnd = windowStart.getTime() + input.windowMs;
  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((windowEnd - now.getTime()) / 1000),
  );

  return {
    allowed: bucket.count <= input.limit,
    remaining: Math.max(0, input.limit - bucket.count),
    retryAfterSeconds,
  };
}

export function rateLimitedResponse(retryAfterSeconds: number) {
  return new Response("Too many requests.", {
    status: 429,
    headers: {
      "retry-after": String(retryAfterSeconds),
      "cache-control": "no-store",
    },
  });
}
