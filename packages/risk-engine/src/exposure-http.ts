/** Analyze caller-supplied response headers without contacting any host. */
export type HttpSecurityHeaderInventory = {
  strictTransportSecurity: "PRESENT" | "MISSING";
  contentSecurityPolicy: "PRESENT" | "MISSING";
  xContentTypeOptions: "PRESENT" | "MISSING";
  referrerPolicy: "PRESENT" | "MISSING";
};

export function inventoryHttpSecurityHeaders(
  headers: Readonly<Record<string, string | undefined>>,
): HttpSecurityHeaderInventory {
  const normalized = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));
  const status = (name: string): "PRESENT" | "MISSING" =>
    normalized.get(name)?.trim() ? "PRESENT" : "MISSING";
  return {
    strictTransportSecurity: status("strict-transport-security"),
    contentSecurityPolicy: status("content-security-policy"),
    xContentTypeOptions: status("x-content-type-options"),
    referrerPolicy: status("referrer-policy"),
  };
}

export function inspectXContentTypeOptions(value: string | null | undefined): "NOSNIFF" | "MISSING" | "INVALID" {
  if (value == null || value.trim() === "") return "MISSING";
  return value.trim().toLowerCase() === "nosniff" ? "NOSNIFF" : "INVALID";
}
