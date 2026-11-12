# Fase 5 — Google Workspace offline, contratos y evaluación conservadora

**Issue:** [#87](https://github.com/txemisys/cyberpilot/issues/87)  
**PR:** [#212](https://github.com/txemisys/cyberpilot/pull/212)  
**Estado:** entregas offline A/B implementadas. La aceptación técnica y la fusión dependen de los checks del HEAD definitivo. No se certifican llamadas a proveedores reales.

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

## Desarrollo funcional de la fase 5

El desarrollo offline incluye ahora estos componentes integrados:

- **Conexión LAB por organización:** máquina de estados versionada
  con nonce de desafío, denegación, aceptación exclusivamente LAB,
  revocación, suspensión, caducidad, rotación de reto y auditoría CAS.
  La aceptación LAB no sustituye el consentimiento OAuth Google.
- **Persistencia y RBAC:** tablas Prisma/PostgreSQL para conexión,
  cadena de auditoría y snapshots de evaluaciones sintéticas, con
  transacciones serializables y aislamiento estricto por organización.
  No se guarda el correo en claro en los snapshots normalizados ni
  un token real de Google.
- **Evidencias neutrales:** proyección de controles, cobertura,
  findings, historia y exportaciones JSON/CSV que conserva
  UNKNOWN/ERROR y procedencia del proveedor, sin recalcular el
  CyberScore canónico.
- **Producto accesible:** la página autenticada
  `/organizations/[slug]/google-workspace` permite crear/consultar
  una conexión LAB, gestionar sus retos, ejecutar un escenario,
  filtrar hallazgos y cobertura, revisar trazas y comparar snapshots.
  Para auditoría/uso de APIs: `/api/organizations/[slug]/google-workspace/offline`
  y `/api/organizations/[slug]/google-workspace/scenarios`.
- **Simulación de Admin SDK:** 17 escenarios deterministas con
  páginas, fallos de permisos 403, límites y reintentos 429,
  respuestas parciales o malformadas, Reports truncados, MFA
  ausente, administradores y dominios. Solo peticiones a un fetcher
  inyectado que nunca envía tráfico a Google.
- **Aceptación automática A+B:** `phase5-acceptance-matrix.ts`
  ejecuta toda la matriz y genera controles técnicos, mientras
  `phase5-release-gate.ts` produce un veredicto verificable y un
  manifiesto local. CI y el workflow independiente
  `.github/workflows/phase5-google-development-closeout.yml`
  comprueban la matriz. El artefacto publicado, si se genera,
  **no constituye firma externa ni aprobación del cliente**.

## Criterios de cierre A+B

Para aceptar **el desarrollo offline** se requieren conjuntamente:

1. Los 17 escenarios y sus aserciones específicos se ejecutan
   correctamente y la matriz no tiene bloques pendientes.
2. Se mantienen los límites de solo lectura y de alcance sintético,
   el control por pertenencia organizativa y revisiones CAS.
3. No se almacenan secretos OAuth ni correos sin redactar en
   los informes; los snapshots tienen retención y procedencia.
4. El informe de pyme y la proyección neutral de evidencias
   muestran limitaciones de permisos, cuotas, 2SV y Reports,
   sin transformar UNKNOWN en un resultado HEALTHY.
5. El workflow `Phase 5 Google development closeout` y los cinco
   workflows habituales `CI`, `Security`, `Local stack E2E`,
   `LAB browser journey`, `Backup restore rehearsal`
   terminan SUCCESS **sobre el mismo HEAD**, antes de fusionar.

Una aceptación técnica verde habilita la **consideración del
merge**, pero ningún artefacto declara autorización empresarial,
seguridad certificada o despliegue en cliente. Un cambio posterior
al HEAD obliga a repetir los checks.

## Alcance LIVE diferido

Permanece fuera del cierre offline:

- OAuth Google real con consentimiento verificable de un
  administrador autorizado; almacenamiento/revocación seguros
  de credenciales reales conforme a la arquitectura de producto.
- Validación de licencias, permisos y cuotas con un tenant real,
  y sincronización real de Directory/Reports.
- Pruebas del recorrido de cliente en un Google Workspace real,
  obligaciones operativas de privacidad/retención y aprobación
  de despliegue. Estas obligaciones no se simulan ni se firman
  automáticamente.
- Calibración de una versión definitiva del CyberScore multifuente.
  La presente fase no modifica el modelo histórico.

La documentación funcional y los tests hacen explícita esta
separación para evitar confundir un desarrollo offline aceptado
con un proveedor LIVE certificado.
