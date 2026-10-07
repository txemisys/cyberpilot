import { createHash, randomUUID } from "node:crypto";

type LogLevel = "info" | "warn" | "error";

type OperationalEventInput = {
  event: string;
  level?: LogLevel;
  organizationId?: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  error?: unknown;
};

const SENSITIVE_KEY =
  /(authorization|cookie|token|secret|password|credential|client.?secret|access.?token|refresh.?token|id.?token)/i;

function sanitizeValue(value: unknown, depth = 0): unknown {
  if (depth > 5) {
    return "[TRUNCATED]";
  }

  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => sanitizeValue(item, depth + 1));
  }

  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};

    for (const [key, child] of Object.entries(value)) {
      output[key] = SENSITIVE_KEY.test(key)
        ? "[REDACTED]"
        : sanitizeValue(child, depth + 1);
    }

    return output;
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    value === null
  ) {
    return value;
  }

  return String(value);
}

export function sanitizeOperationalMetadata(
  metadata: Record<string, unknown> | undefined,
) {
  return metadata ? (sanitizeValue(metadata) as Record<string, unknown>) : {};
}

export function hashOperationalIdentifier(value: string) {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function safeErrorSummary(error: unknown) {
  if (!(error instanceof Error)) {
    return {
      name: "UnknownError",
    };
  }

  const value = error as Error & { status?: unknown };

  return {
    name: error.name || "Error",
    ...(typeof value.status === "number" ? { status: value.status } : {}),
  };
}

export function reportOperationalEvent(input: OperationalEventInput) {
  const level = input.level ?? "error";
  const record = {
    timestamp: new Date().toISOString(),
    eventId: randomUUID(),
    level,
    event: input.event,
    ...(input.organizationId
      ? {
          organizationRef: hashOperationalIdentifier(input.organizationId),
        }
      : {}),
    ...(input.resourceId
      ? {
          resourceRef: hashOperationalIdentifier(input.resourceId),
        }
      : {}),
    metadata: sanitizeOperationalMetadata(input.metadata),
    ...(input.error ? { error: safeErrorSummary(input.error) } : {}),
  };

  const line = JSON.stringify(record);

  if (level === "info") {
    console.info(line);
  } else if (level === "warn") {
    console.warn(line);
  } else {
    console.error(line);
  }

  return record;
}
