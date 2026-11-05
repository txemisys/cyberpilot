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

## Tercer incremento: notificaciones derivadas de eventos e inspección

- `POST .../event-notifications`: reconciliación explícita por captura de eventos persistidos de resolución humana y verificaciones reales de proveedor, con previsualización por defecto, páginas limitadas, topes de fuentes y destinatarios, revalidación transaccional de organización, evento y membresía, deduplicación por origen y destinatario y auditoría de cada publicación.
- `GET .../notification-inspection`: inspección de procedencia y coherencia por página, con comprobación de existencia de tarea, destinatario, evento de revisión, resultado de proveedor o escalado; auditoría de creación, tipo, dedupe, destinatario, timestamps y revisiones; digest SHA-256 de los resultados.
- `IntegrityEventOperations`: interfaz para previsualizar, ejecutar el despacho in-app y consultar los resultados de integridad, integrada en el workspace.
- Pruebas de planificación determinista, seguridad multitenant, reintentos, consistencia de auditoría y persistencia PostgreSQL.

La reconciliación **no se ejecuta automáticamente**: debe activarla un administrador. El tipo histórico `PROVIDER_RECOVERED` representa un resultado PASS en un evento concreto; **no prueba que existiera un fallo anterior ni que la postura actual sea segura**. La inspección es de integridad operacional y tampoco sustituye a la verificación técnica independiente. No se envían mensajes externos.

## Cuarto incremento: manifiestos e indicadores de entrega

- `GET .../operations-manifest`: manifiesto operativo por captura, con paginación de 20 tareas por defecto (máximo 50), cinco categorías de registros, orden determinista, digest SHA-256 por tarea y página, sin cuerpos de notificaciones ni payloads de proveedor. Los IDs de destinatario y asuntos del proveedor se representan como hashes.
- `GET .../delivery-diagnostics`: diagnósticos de la bandeja interna con agrupación por tipo, tarea o destinatario seudonimizado, antigüedad de mensajes sin leer, medianas de lectura, revisiones anómalas, límites de hasta 20.000 registros y aviso de truncamiento.
- `IntegrityOperationsReports`: controles para generar manifiestos y analizar la bandeja desde el workspace, disponibles únicamente para administradores.
- Los dos informes se restringen a la organización autenticada; no constituyen prueba de entrega fuera de la aplicación ni acreditación de seguridad.
- Pruebas de determinismo de digests, minimización de datos, agrupación, validación estricta y truncamiento.

El manifiesto describe estados operativos mutables, por lo que el digest permite detectar diferencias entre dos lecturas, **no** demuestra inmutabilidad criptográfica de la base de datos. Los límites por categoría son explícitos y un resultado truncado no debe interpretarse como completo.

## Quinto incremento: investigación SLA y coherencia del workflow

- `GET .../sla-report`: investigación administrativa y acotada por organización/captura, con umbrales configurables para primera respuesta, resolución, lectura interna y reconocimiento de escalado; distingue incumplimientos activos e históricos, expone digest y advierte si las consultas están truncadas.
- `GET .../workflow-consistency`: auditoría de revisiones, secuencias de eventos, estados terminales, fechas de creación/lectura, cierre de escalados y orden temporal; devuelve hallazgos tipados por tarea, digest por tarea y página, paginación y señalización de cobertura parcial.
- `IntegrityOperationalAssurance`: interfaz administrativa para ambos informes, con filtros y navegación por páginas.
- Los indicadores de lectura se refieren únicamente al estado almacenado en la aplicación, no a la atención humana ni a una entrega externa.
- Los umbrales son de diagnóstico y no equivalen a acuerdos contractuales de servicio.
- No se modifican datos, decisiones de revisión, resultados de proveedor ni CyberScore.

## Sexto incremento: simulación de políticas y antigüedad de bandeja

- `GET .../escalation-simulation`: simulador administrativo **solo lectura** que evalúa la política de escalado con umbrales por severidad, repetición, nivel máximo y horizonte futuro configurable (hasta 720 horas). Rechaza escalados propuestos para revisiones cerradas, sin propietario, con escalado activo o que hayan alcanzado el nivel máximo; devuelve motivos, fechas, huellas SHA-256, límites y paginación.
- `GET .../notification-aging`: diagnóstico de antigüedad de notificaciones persistidas, con filtros de edad, estado, captura, agrupación por tipo/tarea/destinatario seudonimizado/rango de edad, indicadores de concentración y anomalías temporales. Los agregados describen **únicamente la página consultada**.
- `IntegrityPolicyDiagnostics`: interfaz para ajustar umbrales, simular resultados y consultar la antigüedad de la bandeja, integrada en operaciones.
- Ambas rutas exigen permisos administrativos y restringen todas las consultas a la organización autenticada. No se persisten decisiones simuladas ni se emiten mensajes.
- Pruebas unitarias de elegibilidad, bloqueos, fechas, digests, límites y clasificación de edades.

La simulación futura presupone que el estado de la revisión y sus escalados no cambia; no es una predicción de resultados reales ni una programación automática. Los hashes de destinatarios son seudónimos y no deben considerarse anonimización irreversible.
