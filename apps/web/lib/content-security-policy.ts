const BASE_DIRECTIVES = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "media-src 'self'",
  "frame-src 'none'",
];

export function normalizeCspReportUri(value: string | undefined) {
  const candidate = value?.trim();

  if (!candidate) {
    return undefined;
  }

  if (/[;\r\n]/.test(candidate)) {
    return undefined;
  }

  if (candidate.startsWith("/")) {
    return candidate.startsWith("//") ? undefined : candidate;
  }

  try {
    const url = new URL(candidate);

    return url.protocol === "https:" ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

export function buildContentSecurityPolicy(reportUri?: string) {
  const directives = [...BASE_DIRECTIVES];
  const normalizedReportUri = normalizeCspReportUri(reportUri);

  if (normalizedReportUri) {
    directives.push("report-uri " + normalizedReportUri);
  }

  return directives.join("; ");
}
