# CyberPilot — Fase 2: Baseline persistente y autorización de Exposure

**Fecha:** 13 de noviembre de 2026  
**Trabajo:** [PR #217](https://github.com/txemisys/cyberpilot/pull/217)  
**Roadmap:** [Baseline #85](https://github.com/txemisys/cyberpilot/issues/85),
[Exposure #84](https://github.com/txemisys/cyberpilot/issues/84)

## Objetivo

Convertir el diagnóstico declarativo offline en un flujo con estado
duradero y responsable. Separadamente, dotar al módulo Exposure de
un mecanismo seguro de generación, comprobación y revocación de
pruebas de control del dominio. Ningún flujo certifica seguridad
del cliente, compatibilidad CIS oficial ni una remediación técnica.

## Baseline: progreso y revisiones reales

- `BaselineDraft` conserva una versión de cuestionario por
  organización y número de revisión. Se guardan únicamente
  respuestas validadas y referencias documentales opacas.
- `BaselineRevision` conserva de modo independiente cada
  guardado, presentación y reapertura, junto con digest SHA-256
  de respuestas; en una presentación guarda evaluación e informe.
- Las operaciones READ, SAVE, SUBMIT, REOPEN, HISTORY, REVISION
  y COMPARE aplican membresía real, roles, actualización optimista
  y transacción con evento de auditoría del mismo commit.
- OWNER/ADMIN/MEMBER pueden guardar y presentar; AUDITOR solo
  puede consultar. Las colisiones de revisión se rechazan y
  nunca pisan silenciosamente la versión vigente.
- Las notas libres no se guardan. No se interpretan las
  declaraciones afirmativas como comprobaciones técnicas.
- La pantalla del cuestionario permite cargar, guardar,
  presentar, reabrir, inspeccionar historial y comparar revisiones.
- La migración añade únicamente nuevas tablas; no altera
  `SecurityScore` ni los cálculos históricos v1.

## Baseline: seguimiento de acciones

- `BaselineFollowUp` contiene por control una acción de mejora
  propuesta desde el último informe presentado: prioridad,
  guía, evidencia esperada, responsable, fecha objetivo y estado.
- `BaselineFollowUpEvent` registra cada acción en una secuencia
  de revisión; el evento y la operación se auditan en la
  misma transacción de base de datos.
- Los estados OPEN, IN_PROGRESS, BLOCKED, COMPLETED_REPORTED
  y REOPENED se validan por transición. Una acción finalizada
  **según responsable** no constituye remediación verificada.
- La asignación de responsable comprueba su pertenencia al
  tenant; las pruebas se referencian solo mediante IDs opacos.
- Reejecutar INITIALIZE conserva los avances ya existentes.
  REPORT y EXPORT ofrecen resumen, backlog por áreas, retrasos,
  CSV/JSON/Markdown y digest reproducible.
- El expediente del cuestionario tiene un enlace directo al
  seguimiento, con filtros y auditoría detallada.

## Exposure: autorización y consulta DNS explícita

- La emisión crea un token aleatorio de 32 bytes, un desafío
  `_cyberpilot-verification.<dominio>` o una ruta well-known
  y un plazo máximo de 30 minutos. El servidor guarda
  **solo el digest del desafío**, no el valor secreto.
- ISSUE, REPLACE, REVOKE, EXPIRE, READ, HISTORY y LIST
  respetan administrador de organización, actualización por
  revisión, eventos y auditoría. Rotación invalida el token anterior.
- VERIFY_DNS es una acción separada y explícita que exige el
  token temporal y el estado PENDING. Comprueba su digest
  mediante comparación de tiempo constante antes de resolver
  nada. Solo consulta el TXT del nombre específico del desafío,
  con máximo 4 segundos, sin seguir redirecciones, solicitar
  URLs ni realizar escaneo de puertos.
- El resultado conserva `MATCH`, `MISSING`,
  `AMBIGUOUS`, `TIMEOUT`, `DNS_ERROR`, `EXPIRED`,
  `INVALID_CHALLENGE` u `OVERSIZED` sin declarar una
  seguridad inexistente. La prueba DNS demuestra presencia
  del token en ese momento; **no constituye aceptación legal
  ni certificación de seguridad de los sistemas**.
- El motor independiente de política de colecciones mantiene
  sus límites de IP, redirects, cuotas y ámbito, pero
  **no se utiliza para iniciar escaneos LIVE** automáticamente.
- Un desafío HTTP puede emitirse, pero este PR **no** añade
  verificación HTTP LIVE.

## Pruebas A+B y límites

- Integraciones PostgreSQL de borradores, revisión, rol,
  comparación, guardado de datos minimizados y auditoría.
- Integraciones PostgreSQL de acciones, responsables,
  estados, concurrencia y separación por organización.
- Pruebas offline de protocolo DNS/HTTP de autorización,
  límites de cuota, direcciones privadas y redirecciones.
- Verificación DNS en pruebas con **resolver simulado**:
  expiración, token incorrecto, record ambiguo, timeout,
  exceso de tamaño y ausencia de consulta sin autorización.
- Comprobaciones generales CI y aceptación independiente
  `Phase 2 Baseline persistence and Exposure proof closeout`
  sobre el mismo HEAD antes de fusión.

**No verificable mediante CI:** consentimiento de un cliente real,
licencias, autoridad legal, disponibilidad DNS real, funcionamiento
en todas las configuraciones del cliente o un despliegue LIVE.
El acceso LIVE a otros proveedores se mantiene desacoplado.
