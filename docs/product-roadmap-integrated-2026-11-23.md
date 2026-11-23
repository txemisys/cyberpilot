# CyberPilot — roadmap integrado de producto, arquitectura y preproducción

Actualizado: 2026-11-23. Fuente técnica de partida: `docs/deployment-readiness.md`, `docs/remediation.md`, `docs/backup-restore.md`, `docs/content-security-policy.md`, y PR #225.

## Política de ejecución

- Primero funcionalidades realmente ejecutables sin tenants, con pruebas negativas, persistencia, RBAC y evidencia verificable.
- No declarar `verified`, `contained`, `purged`, `wiped`, `revoked` o `restored` sin prueba independiente del proveedor o del entorno real.
- Primer piloto LIVE M365 es read-only, sin credenciales de executor. La remediación que escribe permanece tras consentimiento específico, evaluación de riesgo y autorización.
- CyberScoreV1 no se reinterpreta: scoring multi-fuente requiere contrato propio de versionado.
- Cada bloque de producción C apunta a más de 1.000 líneas netas de funcionalidad real, excluyendo tests/documentación; aceptación depende de CI exacta y no de volumen de código.

## Orden de trabajo aprobado

### A — Incidentes guiados (máxima prioridad; sin tenants)
1. Motor tipado y versionado de cinco playbooks: cuenta comprometida, phishing, ransomware, dispositivo perdido y fraude en pagos.
2. Cada paso exige intención, fuente/procedencia, responsable, criticidad, instrucciones, evidencia para comprobar y limitaciones explícitas. La ausencia de telemetría devuelve UNKNOWN/UNAVAILABLE, jamás falsos negativos.
3. Casos de incidente multi-tenant con comandos CAS, eventos de auditoría, idempotencia, relación con los casos de decisión y acciones ya existentes, aprobación separada para operaciones de riesgo y exportación segura.
4. UI para gestionar incidentes, guía operacional, recopilación de evidencia y revisión, con LAB/browser acceptance.
5. No incluir escritura a Microsoft Graph, bloqueo de remitentes, purga, borrado o aislamiento real sin permisos verificados y executor separado.
6. Aceptación: concurrencia, estados imposibles, aislamiento, replay, evidencia incompleta, CSV/JSON y browser autenticado.

### B — Operaciones resilientes (alta/crítica)
1. Contrato de trabajos persistentes con leases y fencing tokens, deduplicación, retries/backoff acotado, dead-letter, trazabilidad y métricas.
2. Preparar BullMQ/Redis cuando el despliegue requiera procesamiento asíncrono; `render.yaml` al 2026-11-23 solo ofrece web + PostgreSQL, **no** Key Value.
3. RPO y RTO definidos por tier, metodología de medición, drills recurrentes y expediente de restore del proveedor gestionado. Ya existe CI PostgreSQL dump→restore aislado semanal; no equivale a DR real. Gate crítica antes de prod.
4. RBAC por tipo de evidencia/acción, segregación de aprobación y ejecución, no solo OWNER/ADMIN por organización.
5. Audit log export compatible con SIEM: esquema versionado, paginación, marcas temporales y controles de privacidad; luego conectores Splunk/Sentinel/Datadog.

### C — Calidad y hardening (alta/crítica preproducción)
1. Scripts útiles de cobertura, E2E, seed LAB idempotente, typecheck por paquete y lint fix solo cuando exista un linter. No añadir scripts falsamente verdes.
2. Contract tests M365 sobre respuestas Graph, paginación, throttling, permisos, expiración y delta. Considerar MSW/Pact según frontera real.
3. Property-based tests para engine de incidentes/riesgo y mutation tests selectivos (Stryker) en scoring, approval, CAS y executor.
4. ADRs cortos en `docs/adr/` para decisiones costosas: cola, aislamiento, webhooks/delta, CSP, datos, aprobaciones.
5. CSP actual es Report-Only y permite `unsafe-inline`: pasar a nonce/hash y enforcement después de validar staging.
6. Penetration test externo con alcance y remediación de hallazgos antes de piloto sensible; segundo alcance específico del remediation executor antes de permitir escrituras.
7. Secret/token rotation documentada; completar simulaciones y drills, con protección de secretos y rollback.
8. mTLS entre servicios solo si topología real lo necesita; no afirmar aislamiento de red por una opción de hosting.
9. Habilitar Dependency Review cuando GitHub Dependency Graph/alerts sea compatible.

### D — LIVE controlado (dependiente de tenants y permisos)
1. Primer tenant: read-only, privilegios mínimos, consentimiento y observabilidad.
2. Graph delta tokens y webhooks/change notifications con renovación, deduplicación, pérdida de eventos y resync reconciliatorio; nunca asumir que push sustituye toda la verificación.
3. Validar scopes, cuotas, retención, acceso de operador, secreto y restore real en managed staging.
4. Habilitación individual de acciones de alto impacto tras aprobación y pruebas. No declarar revocación, purga, aislamiento, wipe ni respuesta completada a partir de instrucciones guiadas.

### E — Producto comercial y escala (post-piloto salvo diseño)
1. CyberScore Check gratuito: diseño de oferta de solo lectura, tres findings, coste por tenant y límites antes de habilitar onboarding abierto.
2. Partner MSP/MSSP: delegación por cliente, pertenencia, auditoría entre organizaciones, facturación y límites.
3. Teams/Slack: primero alertas/enlaces; aprobaciones desde chat solo con identidad y verificación fuerte antirreplay.
4. Marketplace de playbooks/plantillas: catálogo firmado, versiones y revisión de contenido antes de aceptar publicaciones externas.
5. Deploy EU/US multi-región cuando existan requisitos contractuales de residencia de datos, retención y operación reales.
6. Bug bounty postlaunch una vez exista recepción, triage, SLA y respuesta a vulnerabilidades.

## Estado y dependencias verificadas

- Fase 3C: notificaciones internas y escalados (sin correo/push LIVE).
- Fase 4: Assets offline y OSV, no EDR ni MDM.
- Fase 5: Google Workspace offline, sin consentimiento externo.
- PR #225: caso→acción, timeline de capturas, matriz de fallos y ensayo PostgreSQL en CI.
- CSP Report-Only: `docs/content-security-policy.md`; backup CI: `docs/backup-restore.md`.
- Remediation executor M365: separación de aplicaciones y aprobaciones existente, sin autorización general de acciones destructivas.
- Este documento describe prioridad y aceptación futura; **no** certifica cumplimiento LIVE ni resultados de pen-test.

## Criterios para reordenar

Cambiar prioridad solo ante evidencia medible de producto, carga de jobs, acuerdo de residencia o bloqueo de seguridad. Cada issue indicará: fase, valor cliente, funcionalidad real, negativa de permisos, datos alterados, cobertura de tests, líneas netas significativas, workflows en SHA y límites restantes.
