# Fase 3C — Notificaciones internas y escalados

## Contrato funcional

- Bandeja interna por usuario y organización, lectura paginada, filtros, contadores por tipo, estados leído/no leído/descartado/restaurado, revisiones optimistas y auditoría.
- Publicación explícita por administrador, destinatario con membresía en la misma organización, deduplicación por clave y comprobación de contenido en reintentos.
- Escalados de revisión con umbrales por severidad: ERROR 12 h, WARNING 48 h, INFO 120 h, repetición cada 24 h, nivel máximo 3; configuración validada en cada solicitud.
- Ciclo de vida OPEN → ACKNOWLEDGED → RESOLVED o CANCELLED; REOPEN desde RESOLVED/CANCELLED, con compare-and-swap por revisión y auditoría.
- Despacho manual por captura con previsualización por defecto, lote limitado, destinatarios administradores y propietario de revisión si pertenece a la organización, revalidación de estado dentro de la transacción, deduplicación por nivel y destinatario.
- La notificación se persiste **solo en la aplicación**. No se envían correos, SMS ni notificaciones push. No existe todavía un proceso periódico que despache automáticamente los vencimientos.
- No se modifica automáticamente la disposición de revisión, estado de hallazgo, remediación ni CyberScore.

## Endpoints

Todos requieren sesión y membresía en la organización.

- `GET /api/organizations/{slug}/actions/work/integrity/notifications` — bandeja del usuario actual; `?summary=true` para contadores.
- `POST .../notifications` — publicación por administrador.
- `PATCH .../notifications` — marcar leído, no leído, descartar o restaurar con `expectedRevision`.
- `GET .../escalations` — listado; `?mode=summary` para contadores, `?mode=preview&captureId=...` para candidatos sin persistencia.
- `POST .../escalations` — abrir escalado vencido.
- `PATCH .../escalations` — transición auditada.
- `POST .../escalation-dispatch` — previsualización o despacho in-app de una página de tareas de una captura; `dryRun=false` requiere ADMIN/OWNER.

## Seguridad y aceptación

La consulta de bandeja siempre filtra por `recipientUserId` del usuario autenticado; las consultas de escalados y capturas se restringen por `organizationId`. El destinatario de publicaciones debe tener membresía en la organización. Los comandos usan revisiones CAS y los registros generan eventos de auditoría.

Las pruebas unitarias cubren entradas inválidas, política, máquina de estados, destinatarios y claves. Las pruebas PostgreSQL cubren persistencia, idempotencia, aislamiento entre organizaciones, revisión concurrente, estados y despacho.

**Pendiente:** interfaz visual integrada en el workspace, experiencia de usuario completa, notificaciones basadas en eventos de revisión y un scheduler autorizado si se desea envío automático. Los checks del PR deben aprobarse antes de fusionar.

## Segundo incremento: operaciones y experiencia de usuario

- `/organizations/{slug}/integrity-operations`: interfaz autenticada enlazada desde el centro de acciones, con bandeja, filtros, cola de revisiones, acciones de triage y ciclo de escalados. Los roles no administradores tienen vista de lectura.
- `GET .../operations-queue`: tareas por organización y captura, vencimientos, buckets, indicadores de trabajo vinculado, comprobaciones de proveedor, escalados y notificaciones. La paginación se realiza en base de datos y los filtros de bucket y ordenación se aplican **solo a la página consultada**.
- `POST .../review-triage`: lote de hasta 50 comandos, previsualización por defecto, asignar/desasignar, recordatorio interno y notificación a propietario/administradores, aislamiento de tenant, auditoría y protección de reintentos. La asignación **no incrementa la revisión de la máquina de estados**, para preservar el ledger de eventos de revisión; se compara el propietario previo.
- `GET .../review-triage?taskId=...`: historial paginado de acciones de triage.
- `GET .../operations-metrics`: serie temporal UTC diaria/semanal de revisiones, notificaciones, escalados y verificaciones del proveedor, digest reproducible, rango limitado a 366 días y tope de 20.000 registros por categoría señalado en la respuesta.

### Limitaciones

Las métricas son operativas y no equivalen a mejoras del CyberScore. La cola muestra el último resultado del proveedor como contexto, sin afirmar vigencia técnica del gate. El despacho automático periódico y los canales externos no se han implementado. Los lotes de triage son transaccionales por comando, no como grupo. El cierre completo del Bloque C exige validación de experiencia visual, pruebas de usuario y la política de notificaciones por evento.
