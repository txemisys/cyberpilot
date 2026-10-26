/** Validate a zero-based guided playbook step submitted by a form. */
export function parseGuidedStepIndex(value: FormDataEntryValue | null, stepCount: number): number | null {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const index = Number(value);
  if (!Number.isSafeInteger(index) || index >= stepCount) return null;
  return index;
}
