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
