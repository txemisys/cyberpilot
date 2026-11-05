# Fase 3C — Matriz de cierre y aceptación

Fecha de revisión: 2026-11-05
PR de implementación: #210, rama `feat/phase3-block-c`

## Decisión de alcance

El bloque C entrega operaciones internas de notificación, escalado, triage,
intervenciones auditadas, informes de investigación y experiencia de usuario.
No incluye correo, SMS, push, programación periódica de acciones ni ejecución
desatendida. Esas funciones requieren un diseño de ejecución LIVE, políticas
de credenciales y consentimiento, y autorización de despliegue independientes.

No se interpreta el estado RESOLVED ni el resultado histórico PASS como una
acreditación de seguridad. Ninguna acción de este bloque modifica CyberScore.

## Matriz de entrega

| Capacidad | Artefacto | Verificación automatizada | Estado |
|---|---|---|---|
| Bandeja individual y transiciones CAS | `work-integrity-notifications.ts` | `work-integrity-phase3c.test.ts`, `work-integrity-phase3c.integration.test.ts` | Implementada |
| Escalados persistentes y despacho explícito | `work-integrity-escalations.ts`, `work-integrity-escalation-dispatch.ts` | Pruebas fase 3C | Implementada |
| Triage en lotes, membresía, idempotencia y auditoría | `work-integrity-review-triage.ts` | `work-integrity-operations-c.integration.test.ts` | Implementada |
| Notificaciones derivadas de revisión/proveedor | `work-integrity-event-notifications.ts` | `work-integrity-events-c.integration.test.ts` | Implementada, manual |
| Inspección de procedencia y manifiestos | `work-integrity-notification-inspection.ts`, `work-integrity-operations-manifest.ts` | Pruebas de informes | Implementada |
| Métricas, SLA y coherencia de workflow | `work-integrity-operations-metrics.ts`, `work-integrity-workflow-consistency.ts` | Pruebas de informes | Implementada |
| Simulación de políticas y antigüedad | `work-integrity-escalation-simulation.ts`, `work-integrity-notification-aging.ts` | Pruebas diagnósticas | Implementada |
| Planificación y comparación de capturas | `work-integrity-operational-planning.ts`, `work-integrity-capture-cohorts.ts` | `work-integrity-operational-planning.test.ts` | Implementada |
| Ejecución administrativa consentida | `work-integrity-interventions.ts` | Pruebas unitarias y PostgreSQL | Implementada |
| Historial de intervenciones | `work-integrity-intervention-history.ts` | Pruebas unitarias y PostgreSQL | Implementada |
| Diagnóstico de aceptación por captura | `work-integrity-phase3c-acceptance.ts` | Pruebas unitarias y PostgreSQL | Implementada |
| Plan de investigaciones sin ejecución | `work-integrity-phase3c-acceptance-plan.ts` | Pruebas unitarias | Implementada |
| UI integrada | `apps/web/app/organizations/[slug]/integrity-operations/page.tsx` | Build y journey LAB existentes | Implementada; validación humana pendiente |

La presencia de pruebas y build correcto no garantiza que cada ruta y cada
interacción haya sido ejecutada en un navegador autenticado. El LAB existente
no debe interpretarse como aceptación humana integral.

## Puerta de diagnóstico operacional

La ruta `GET /api/organizations/{slug}/actions/work/integrity/phase3c-acceptance`
exige permisos ADMIN/OWNER y `captureId`. Devuelve tareas, hallazgos
tipados por severidad, total y paginación, digest SHA-256 y un plan de
investigación. Los registros se filtran por organización y captura.

`BLOCKED` significa que la página inspeccionada contiene contradicciones
estructurales; `REQUIRES_REVIEW` incluye hallazgos revisables, páginas
incompletas o capturas sin tareas; `READY_FOR_MANUAL_ACCEPTANCE` solo
significa que el diagnóstico de la página completa no detectó anomalías
estructurales o advertencias. No equivale a aprobación del despliegue.

Los límites de registros relacionados se tratan de forma conservadora:
si se alcanza el tope de inspección, la respuesta marca cobertura incompleta
y no puede declararse lista para aceptación.

## Criterios de aceptación manual pendientes

- [ ] Probar en un despliegue autenticado roles OWNER, ADMIN, MEMBER y AUDITOR.
- [ ] Verificar filtrado de bandeja, read/unread, dismiss/restore.
- [ ] Abrir, reconocer, resolver, cancelar y reabrir un escalado.
- [ ] Previsualizar un despacho y verificar ausencia de escrituras.
- [ ] Confirmar un despacho, observar su persistencia y reintentar la clave.
- [ ] Validar concurrencia real entre dos operadores en una misma tarea.
- [ ] Probar asignación, desasignación y notificación de triage.
- [ ] Probar la consola de intervención con aprobación explícita y sin ella.
- [ ] Inspeccionar el historial y confirmar ausencia de datos de otros tenants.
- [ ] Verificar claridad de avisos de evidencia parcial y de resultados de proveedor.
- [ ] Obtener revisión formal del producto y autorización de fusión.
- [ ] Verificar que el PR actual tiene los cinco workflows correctos.

## Invariantes para aceptar

1. Todas las lecturas, escrituras y eventos deben conservar `organizationId`.
2. El usuario no puede actuar sobre una tarea fuera de su captura/organización.
3. La transición de estado usa la revisión esperada; la asignación también
   comprueba el propietario esperado dentro de su transacción.
4. Un reintento con la misma clave y datos no repite el cambio; una clave
   reutilizada con datos distintos produce conflicto.
5. El despacho solo crea notificaciones dentro de la aplicación; no afirma
   entrega humana, correo ni mejora del control subyacente.
6. La interfaz distingue previsualización de persistencia y exige confirmación.
7. La decisión de aceptación conserva el carácter provisional de páginas
   parciales, registros truncados y pruebas sin validación humana.

## Estado de cierre

La implementación del contrato funcional está disponible en el PR #210.
Los checks deben inspeccionarse sobre el HEAD final, no sobre commits previos.

**Cierre de implementación:** condicionado a checks verdes en HEAD final.
**Cierre de aceptación operativa manual:** pendiente.
**Fusión:** pendiente de autorización expresa del propietario.

No marcar el Bloque C como cerrado al 100 % antes de completar los criterios
manuales y verificar el HEAD que se pretenda integrar.
