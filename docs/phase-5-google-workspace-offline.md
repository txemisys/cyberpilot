> **Actualización de desarrollo CCC — 12/11/2026:** desde esta revisión se ha implementado también el onboarding LAB simulado, con desafío de un solo uso, caducidad, denegación, revocación, CAS y auditoría; tablas y migración PostgreSQL para el estado, los eventos y snapshots sintéticos con retención; servicio multitenant de lectura, auditoría, exportación y comparación; proyección neutral de controles/hallazgos sin cambiar CyberScore; y API POST autenticada `/api/organizations/[slug]/google-workspace/offline`. Las secciones históricas de tareas pendientes más abajo describen el estado anterior y deben leerse con esta actualización. No se ha implementado OAuth Google LIVE ni sincronización real de tenant. El PR #212 no se considera cerrado automáticamente por la existencia de estos componentes.

# Fase 5 — Google Workspace offline, contratos y evaluación conservadora

**Issue:** [#87](https://github.com/txemisys/cyberpilot/issues/87)  
**PR:** [#212](https://github.com/txemisys/cyberpilot/pull/212)  
**Estado:** desarrollo progresivo; no se considera cerrada la fase completa ni se certifican llamadas a proveedores reales.

## Propósito

Dotar a CyberPilot de un segundo origen potencial de evidencias de
identidad que no dependa de Microsoft 365. La meta es **equivalencia de
valor**, no equivalencia literal de controles o señales.

La primera entrega implementa los contratos de lectura y evaluación
**sin credenciales Google reales**. El código acepta un transport
inyectado, y en CI se utiliza exclusivamente un adaptador de
respuestas sintéticas. No hay conexión OAuth operativa con un tenant,
no se concede consentimiento y no se almacenan tokens del proveedor.
La API LIVE seguirá siendo un alcance de integración diferenciado.

## Arquitectura implementada

`packages/integrations/src/google-workspace/`:

- `directory-contract.ts`: tipos versionados, capacidades
  `DIRECTORY_USERS`, `DIRECTORY_DOMAINS`,
  `DIRECTORY_ORGANIZATION_UNITS`, `REPORTS_LOGIN`,
  `REPORTS_ADMIN`, `USER_MFA_ATTRIBUTES`; normalización
  y digest de snapshots; preservación de `OBSERVED`, `DECLARED`,
  `UNKNOWN` y `ERROR`; identificación por hash tenant-scoped.
- `transport.ts`: petición GET estrictamente a
  `https://admin.googleapis.com`, consultas permitidas,
  paginación, deadlines, budget total, retry/backoff y rechazos
  conservadores ante permisos insuficientes, respuestas malformadas,
  cortes de página y cuotas; consentimiento explícito del llamante
  e inhibición LIVE por defecto.
- `risk-assessment.ts`: reglas sobre privilegios y atributos 2SV
  expuestos por Directory, actividad antigua, dominios no
  verificados y ausencia de visibilidad audit; hallazgos
  propuestos, cobertura por capacidad y score de previsualización
  *distinto del CyberScore canónico*. No se emite score para
  fixtures ni evidencias incompletas.
- `assessment-report.ts`: once secciones de informe,
  advertencias, manifest y exportaciones JSON/Markdown;
  comparación de snapshots e historia acotada. La desaparición
  de un riesgo **no se presenta como corrección verificada**.
- `index.ts`: export de las capacidades y servicios con tipos.

La UI y la persistencia de una conexión Google real, la autorización
OAuth y el flujo de integración con la puntuación definitiva
multifuente no están incluidos aún. La sola existencia de contratos
no permite afirmar una integración de producto terminada.

## Autorizaciones y fuentes de API

Se han contrastado las rutas REST con la documentación oficial
de Google, no con respuestas de un tenant real:

- [Directory users.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list):
  `GET /admin/directory/v1/users`, con `customer=my_customer`,
  `maxResults` y `pageToken`.
- [Admin SDK Directory REST](https://developers.google.com/workspace/admin/directory/reference/rest):
  listados de dominios y unidades organizativas.
- [Reports activities.list](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list):
  `GET /admin/reports/v1/activity/users/all/applications/login`
  o `admin`, acotado por tiempo y paginación.

La implementación contiene una lista de scopes READONLY, pero
**no** pretende que todos estén concedidos; cada capacidad puede
marcar permisos ausentes, disponibilidad desconocida o error parcial.
La edición/licencia puede determinar qué informes están disponibles.

## Límites de privacidad y seguridad

- No se guardan tokens en los informes o los objetos de resultado.
  Los mensajes de fallo del transporte no incluyen URL con token,
  correo, contenido bruto de respuesta ni cabeceras de autorización.
- La normalización transitoria puede contener correo principal y
  alias como datos de Directorio. El informe exportado utiliza
  hashes de sujeto; no debe persistirse/exportarse el snapshot
  transitorio sin políticas específicas de minimización/retención.
- Los eventos audit se resumen sin IP o correo bruto del actor y
  excluyen parámetros con nombres sensibles.
- Los scopes, licencias y permisos incompletos producen estados
  UNKNOWN/ERROR. No se presenta cobertura parcial como HEALTHY.
- Ninguna regla remedia cuentas ni modifica permisos; las acciones
  se devuelven con `PROPOSED_ONLY` y requieren autorización del
  cliente cuando se utilizan.
- No se realiza descubrimiento activo ni se toca el CyberScore
  existente.
- Ni fixtures, ni hash local, ni ejecución verde en CI equivalen
  a firma externa, tenant Google real o certificación.

## Aceptación A/B del roadmap

El desarrollo puede progresar con tests offline y verificaciones
automáticas; la aceptación operativa C no bloquea el desarrollo.
El issue #87, sin embargo, también contempla conexión simulada,
controles de consentimiento/revocación, pertenencia organizativa,
fuentes normalizadas e informes. La primera entrega cubre parte
de esos criterios; **no debe cerrarse el issue hasta completar
la funcionalidad de onboarding/persistencia y su integración**.

Verificaciones automáticas:
- validaciones de respuestas Directory/Reports, digest y
  separaciones entre tenant y fuentes;
- transporte inyectado, permisos 403, límites, retries y
  rechazo de redirecciones;
- casos MFA desconocido, privilege y usuario suspendido;
- informe JSON/Markdown, integridad y comparación prudente
  de snapshots;
- CI, Security y LAB completos al HEAD de cada ronda.
Los checks que no se hayan ejecutado no deben presentarse
como exitosos.

## Trabajo siguiente

1. Crear flujo de conexión Google Workspace *simulada*
   asociado a una organización con control de acceso y
   auditoría; consentimiento denegado/revocado, expiración
   y revocación con rechazo de replays.
2. Persistir snapshots y evidencias normalizadas tenant-scoped,
   con versión de fuente, retención y políticas PII verificables.
3. Conectar findings y coverage de Google al contrato neutral
   de evidencia, sin alterar indebidamente la versión histórica
   del CyberScore.
4. Probar la experiencia web, el informe ejecutivo de varias
   fuentes, el manejo de cuotas y la falta de licencias.
5. Cuando A+B esté completo, utilizar el gate automatizado
   del roadmap y fusionar; las comprobaciones LIVE de un
   Google Workspace autorizado quedan para nivel C.
