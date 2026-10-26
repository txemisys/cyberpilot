/** Acknowledgements signal readiness to request new evidence, never a verified fix. */
export function getGuidedVerificationReadiness(
  stepCount: number,
  acknowledgedSteps: ReadonlySet<number>,
): "NO_STEPS" | "IN_PROGRESS" | "READY" {
  if (stepCount === 0) return "NO_STEPS";
  for (let index = 0; index < stepCount; index++) {
    if (!acknowledgedSteps.has(index)) return "IN_PROGRESS";
  }
  return "READY";
}
