# Fase 3 — Bloque A: criterios de aceptación y cierre técnico

Fecha de evaluación: 2026-11-03. PR de integración: [#208](https://github.com/txemisys/cyberpilot/pull/208).

## Alcance y límites

El Bloque A abarca el **workflow de revisión de integridad persistente**, no la totalidad de la Fase 3 ni las herramientas analíticas offline del mismo PR. Su finalidad es registrar tareas vinculadas a capturas completas, asignar responsables mediante reconocimiento, transicionar estados, conservar comandos idempotentes, eventos y auditorías, y permitir la inspección del historial.

El estado RESOLVED indica **decisión administrativa**, no corrección técnica independiente. Una referencia a `SecurityEvidence` acredita existencia en la organización, no vigencia, veracidad, ni eficacia de una remediación. La inspección del ledger detecta inconsistencias en datos persistidos, **no proporciona firma criptográfica** ni protección frente a un administrador de base de datos malicioso.

## Criterios de aceptación verificables

| ID | Criterio | Implementación / prueba | Estado |
| --- | --- | --- | --- |
| A-01 | Persistir tareas con unicidad por organización, captura e ID externo | `work-integrity-persistent-review.ts`; `work-integrity-persistent-review.integration.test.ts` | Verificado por CI |
| A-02 | Rechazar capturas inexistentes, ajenas o incompletas | `createPersistentReview`, `registerPersistentReviewBatch` | Implementado; pruebas de aislamiento y validación |
| A-03 | Restringir escritura a OWNER/ADMIN y lectura a roles autorizados | `scopeRead`, `scopeWrite`, `assertRead`, `assertWrite`; pruebas de auditor | Verificado por CI |
| A-04 | Restringir toda consulta y modificación al tenant autenticado | `organizationId` en consultas; pruebas cruzadas | Verificado por CI |
| A-05 | Validar transiciones, propietario y prohibición de exención de ERROR | `planReviewTransition`; pruebas unitarias e integración | Verificado por CI |
| A-06 | Evitar escrituras obsoletas y doble aplicación concurrente | `expectedRevision`, actualización condicional, transacción serializable | Verificado por CI |
| A-07 | Repetir comandos con la misma clave y contenido sin crear nuevos eventos | `IntegrityReviewCommand` y `reviewCommandDigest` | Verificado por CI |
| A-08 | Rechazar referencias de evidencia inexistentes o de otro tenant | `applyPersistentReviewCommand`; pruebas PostgreSQL | Verificado por CI |
| A-09 | Crear evento, comando, actualización de tarea y auditoría atómicamente | Transacción serializable; pruebas PostgreSQL | Verificado por CI |
| A-10 | Registrar auditoría individual por cada tarea creada, también en lotes | `registerPersistentReviewBatch`; prueba PostgreSQL | Verificado por CI |
| A-11 | Consultar tareas, eventos, estado detallado y resumen con control de acceso | Rutas `integrity/reviews` y `integrity/reviews/operations` | Compilación y pruebas automatizadas |
| A-12 | Detectar divergencias entre estado, eventos, comandos y auditorías de creación | `work-integrity-persistent-review-ledger.ts`; pruebas unitarias e integración | Verificado por CI |
| A-13 | Aplicar migraciones, comprobar tipos, ejecutar tests y construir la aplicación | Workflow `.github/workflows/ci.yml` | Verificado en commit `7c0d6616e4b3ed4f16ff6dd11ccbed63c72eef48` |
| A-14 | Superar controles Security, LAB, Local stack E2E y Backup | GitHub Actions del mismo commit | Verificado |
| A-15 | Fusionar el PR revisado en `main` | GitHub PR #208 | **Pendiente de autorización explícita y fusión** |
| A-16 | Prueba manual de aceptación en un despliegue con usuario real | No se ha presentado ejecución manual verificable | **Pendiente / no confirmada** |

## Evidencia de ejecución automatizada

Commit `7c0d6616e4b3ed4f16ff6dd11ccbed63c72eef48`:
- CI, Security, LAB browser journey, Local stack E2E y Backup restore rehearsal: **success**.
- CI: migraciones PostgreSQL, TypeScript, tests y build superados.
- Tests web: **3.954** superados; suite de integración de revisión persistente: **17** superados; suite de ledger: **17** superados.

Estos resultados acreditan los escenarios ejecutados por los tests, **no** un ejercicio manual de todas las rutas de revisión en producción.

## Condiciones de cierre

- **Cierre técnico del Bloque A:** alcanzado para el alcance y criterios automatizados anteriores.
- **Cierre de integración:** pendiente mientras el PR no esté fusionado.
- **Cierre de aceptación operativa al 100 %:** requiere además una prueba manual o E2E específico de las rutas autenticadas de revisión en un entorno desplegado, si ese nivel forma parte del criterio de aceptación del producto.
- No confundir este cierre con el de la Fase 3 completa ni con la certificación de evidencias externas.

## Secuencia de aceptación manual propuesta

1. Acceder con ADMIN a una organización con captura completa y crear una tarea desde la ruta de revisión.
2. Repetir creación con el mismo ID externo y comprobar respuesta de conflicto.
3. Registrar un lote mixto de tareas nuevas y existentes; verificar auditoría individual y resumen.
4. Reconocer, iniciar revisión y resolver una tarea con referencia `SecurityEvidence` de la misma organización; comprobar revisiones y eventos.
5. Repetir el comando con idéntica clave y contenido; comprobar respuesta reproducida y ausencia de nuevos eventos.
6. Intentar actualización con revisión obsoleta, exención de ERROR y evidencia ajena; verificar rechazo sin cambio de estado.
7. Consultar el ledger y comprobar consistencia; repetir desde otra organización y comprobar aislamiento.
8. Comprobar que un AUDITOR puede consultar pero no modificar.

La ejecución manual de estos pasos **no se afirma realizada**.
