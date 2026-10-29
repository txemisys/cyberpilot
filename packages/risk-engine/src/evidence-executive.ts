import type { EvidenceReport } from "./evidence-report";
import { auditEvidenceReport } from "./evidence-report-audit";
/** Executive summary of provider-neutral evidence, not a security score. */
export type ExecutiveEvidenceSummary = {
  schemaVersion: 1; organizationId: string; coverage: EvidenceReport["coverage"];
  evidence: { total: number; observed: number; declared: number; unknown: number; errors: number };
  priorities: readonly { code: "ERROR_EVIDENCE" | "UNKNOWN_EVIDENCE" | "DECLARED_ONLY" | "UNASSESSED_COVERAGE"; count: number; label: string }[];
  narrative: string[];
};
export function buildExecutiveEvidenceSummary(report: EvidenceReport, organizationId: string): ExecutiveEvidenceSummary | null {
  if (!organizationId || report.organizationId !== organizationId || auditEvidenceReport(report).length) return null;
  const priorities: ExecutiveEvidenceSummary["priorities"][number][] = [];
  if (report.errors) priorities.push({code:"ERROR_EVIDENCE",count:report.errors,label:"Revisar errores de evidencia"});
  if (report.unknown) priorities.push({code:"UNKNOWN_EVIDENCE",count:report.unknown,label:"Completar información desconocida"});
  if (report.declared) priorities.push({code:"DECLARED_ONLY",count:report.declared,label:"Verificar declaraciones cuando sea posible"});
  if (report.coverage !== "COMPLETE") priorities.push({code:"UNASSESSED_COVERAGE",count:0,label:"Ampliar la cobertura de controles"});
  const narrative = [
    "El informe distingue evidencias observadas, declaradas, desconocidas y errores.",
    "Las declaraciones no representan verificaciones técnicas.",
    report.coverage === "COMPLETE" ? "Cobertura completa de los controles esperados para este informe." : report.coverage === "PARTIAL" ? "Cobertura parcial de los controles esperados para este informe." : "No se dispone de cobertura observada de los controles esperados.",
    "Este resumen no calcula ni modifica el CyberScore histórico.",
  ];
  return {
    schemaVersion:1,organizationId,coverage:report.coverage,
    evidence:{total:report.total,observed:report.observed,declared:report.declared,unknown:report.unknown,errors:report.errors},
    priorities,narrative,
  };
}
