# Fase 3 — Bloque B: contrato de aceptación

## Alcance y límites

Bloque B cubre la trazabilidad entre una captura de casos de integridad, la tarea de revisión persistida, la evaluación de evidencia y el trabajo de remediación. Distingue explícitamente la asociación operacional, la decisión humana y la verificación independiente.

**No se considera verificación independiente** una evaluación humana `ACCEPTED`, un digest SHA-256 de un registro de la base de datos, un estado de remediación `VERIFIED` almacenado o un enlace a una tarea `DONE`. La verificación independiente requiere consultar o recibir una respuesta verificable de una fuente autorizada, con permisos, identidad de origen, momento y resultado, y comparar su resultado con el control esperado. Ninguno de esos resultados puede simularse.

## Criterios verificables

| Criterio | Evidencia de implementación | Estado |
| --- | --- | --- |
| B-01. Evaluación persistida de evidencia por organización | `IntegrityEvidenceAssessment` + migración PostgreSQL | Implementado |
| B-02. Acceso de lectura por rol y escritura ADMIN/OWNER | `work-integrity-evidence-assessment.ts` | Implementado |
| B-03. Evidencia de otra organización rechazada | Tests PostgreSQL de evaluación | Implementado |
| B-04. Secuencia optimista e idempotencia sin duplicación | Transacción Serializable, CAS y clave idempotente | Implementado |
| B-05. Digest del snapshot, detección de cambios y auditoría | `observationSnapshot`, `inspectAssessmentEvidence` | Implementado |
| B-06. Evaluación separada del ledger de estados de revisión | `assessmentRevision` separado de `revision` | Implementado |
| B-07. Gates conservadores por tarea y cartera | `work-integrity-evidence-gates.ts` | Implementado |
| B-08. Asociación explícita revisión ↔ trabajo | `IntegrityReviewWorkLink` + migración | Implementado |
| B-09. LINK/UNLINK/RELINK transaccionales con CAS | `work-integrity-review-work-links.ts` | Implementado |
| B-10. Auditoría y replay de asociaciones | `inspectReviewWorkAssociation` | Implementado |
| B-11. Trazabilidad captura → revisión → evidencia → trabajo | `work-integrity-capture-lineage.ts` | Implementado |
| B-12. Diagnóstico de contradicciones operativas | `work-integrity-review-work-reconciliation.ts` | Implementado |
| B-13. APIs autenticadas, filtros limitados y aislamiento | Rutas `evidence-assessments`, `evidence-gates`, `review-work-links`, `capture-lineage`, `review-work-reconciliation` | Implementado |
| B-14. Pruebas PostgreSQL y cinco workflows verdes en HEAD | GitHub Actions para el commit final | Pendiente de validación |
| B-15. Revalidación independiente de un control por proveedor autorizado | Conector en vivo y evidencia verificable de origen | Pendiente |
| B-16. Flujo completo de aceptación operacional en entorno desplegado | Usuario autenticado, permisos reales y datos de origen | Pendiente |
| B-17. Integración aprobada en `main` | PR #209 fusionado tras checks | Pendiente |

## Condiciones de cierre

El Bloque B no estará cerrado al 100 % hasta satisfacer B-14 a B-17. Las pruebas unitarias y de PostgreSQL no sustituyen una comprobación de un proveedor externo ni la aceptación desplegada. No se permite afirmar cierre de hallazgos ni modificar CyberScore basándose únicamente en una aceptación humana.

## Prueba operacional propuesta

1. Iniciar sesión en una organización con OWNER/ADMIN y crear una captura de casos real.
2. Registrar y revisar la tarea; asociar un trabajo de remediación con una justificación.
3. Evaluar evidencia OBSERVED y comprobar digest, auditoría y revisión.
4. Cambiar el registro de evidencia en un entorno controlado; comprobar que el gate indica observación obsoleta.
5. Desvincular y revincular el trabajo; inspeccionar las tres entradas de auditoría.
6. Comprobar que AUDITOR no puede mutar y que otra organización no puede leer ni asociar.
7. Ejecutar la verificación autorizada de proveedor cuando exista; registrar resultado verificable y discrepancias.
8. Confirmar que no se ha modificado CyberScore ni cerrado un hallazgo sin verificación independiente.
