> **Actualización de criterios de cierre — 12/11/2026:** por decisión del proyecto, las fases del **roadmap de desarrollo** se cierran con aceptación técnica automatizada de niveles A+B. Las aprobaciones humanas, decisiones legales, evidencias de un cliente y ensayos operativos reales (nivel C) pertenecen al proceso de despliegue, no constituyen una condición de fusión del código. Las restricciones humanas de uso real siguen activas dentro de CyberPilot. Esta aclaración prevalece sobre cualquier párrafo anterior que exija firmas de clientes u operadores para cerrar el PR de desarrollo. Véase [política de aceptación automática](./development-acceptance-policy.md). La validación A+B debe concluir satisfactoriamente sobre el HEAD final; no se presume por esta nota.

# Fase 4 — Assets: inventario pasivo CSV

Issue de producto: #86. PR inicial: #211.

## Contrato de entrada

El inventario parte de un CSV que aporta la organización. No requiere
Microsoft 365, credenciales externas, agentes de endpoint ni escaneo activo.

Encabezado obligatorio con **nueve columnas**:

```csv
asset_id,hostname,owner,platform,os_name,os_version,software_name,software_version,observed_at
device-001,laptop-001,,WINDOWS,Windows 11,23H2,Example Editor,1.2.3,2026-11-04T12:00:00.000Z
```

Reglas: máximo 256 KiB y 1.000 filas, UTF-8, cabecera exacta, columnas
sin duplicados, comillas y saltos de línea interpretados conforme a CSV,
timestamp UTC con milisegundos, rechazo de caracteres de control y valores
con apariencia de fórmula, límites de longitud y plataformas explícitas.
La pareja `asset_id` + software normalizado es única por importación.
Las filas duplicadas se descartan de modo conservador y se contabilizan.

El campo `owner` **no se guarda en claro**; únicamente se almacena un
hash SHA-256 ligado a la organización. Sigue siendo seudonimización y no
anonimización. Conviene proporcionar identificadores no personales.
El CSV bruto se usa durante la solicitud y no se persiste en las tablas
de inventario. El identificador de host sí puede ser un dato personal.

## Estado y contexto de las observaciones

Cada importación genera una instantánea inmutable con estado COMMITTED.
Cada fila conserva origen, número de fila, identificador declarado,
plataforma, SO, producto, versiones, fecha declarada, estado de versión,
antigüedad calculada y nivel de confianza de la declaración.

Las versiones se clasifican como EXACT, MISSING o AMBIGUOUS. La antigüedad
es FRESH, AGING, STALE o FUTURE; estos estados se calculan respecto al
momento de importación y **no se actualizan en segundo plano**.

El estado de correlación CVE es UNKNOWN cuando falta una versión exacta,
no se ha proporcionado un feed o no hay software declarado; NO_MATCH
significa únicamente que no se encontró coincidencia exacta en **ese feed**.
POSSIBLE_MATCH requiere igualdad exacta del nombre de producto normalizado
y de la versión afectada. Ningún estado prueba que la vulnerabilidad sea
explotable, que el endpoint esté expuesto ni que el producto sea seguro.
No se consulta una fuente externa ni se pretende cobertura global CVE.

La interfaz web incorpora validación/previsualización antes de almacenar
una instantánea. Las operaciones se autorizan con ADMIN/OWNER; MEMBER y
AUDITOR pueden consultar los datos limitados a su organización.
Los datos devueltos identifican expresamente la procedencia
CUSTOMER_DECLARED_CSV.

## Persistencia, concurrencia y auditoría

Los modelos `AssetInventoryImport` y `AssetInventoryDevice` emplean
filtrado por `organizationId`, índice de idempotencia por organización,
unicidad de dispositivo/producto dentro de cada importación y cascada
de borrado desde la organización. Una importación confirmada guarda filas
y evento auditado en una misma transacción.

Repetir una clave de importación con el mismo CSV y feed devuelve el registro
existente. Cambiar el contenido bajo la misma clave es un conflicto, y el
fingerprint de idempotencia no depende del reloj de la solicitud.

La retirada administrativa exige motivo y estado esperado COMMITTED, usa
compare-and-swap y produce auditoría. La retirada **no borra** físicamente
los registros: solo los oculta de las consultas ordinarias. La eliminación
definitiva, retención temporal y política de privacidad requieren una
decisión adicional antes de LIVE.

## Endpoints autenticados

- `GET /api/organizations/{slug}/assets/imports`: instantáneas paginadas.
- `POST /api/organizations/{slug}/assets/imports`: `dryRun` por defecto;
  `dryRun:false` persiste con idempotencia.
- `PATCH /api/organizations/{slug}/assets/imports`: retirada autorizada.
- `GET /api/organizations/{slug}/assets/devices`: observaciones filtradas
  por importación, activo, plataforma, estado de versión y aviso.
- `/organizations/{slug}/assets`: interfaz integrada y autenticada.

## Pruebas y aceptación

Las pruebas unitarias cubren ataques de fórmula CSV, tamaño, comillas,
cabeceras, fechas inválidas, versiones ambiguas, duplicados, normalización
y ausencia de inferencias de seguridad. Las pruebas PostgreSQL cubren
membresía, aislamiento de organizaciones, previsualización sin escrituras,
idempotencia tras avanzar el reloj, auditoría, filtros y retirada.

**Pendiente para aceptar la primera versión de Assets:** validación manual
del flujo de importación con datos sintéticos representativos, política de
retención y borrado definitivo, revisión del tratamiento de PII, conexión
de advisories con fuentes oficiales versionadas si se exige correlación
actualizada, y ampliación de inventario a varias instantáneas con
deduplicación longitudinal.

Este bloque no actualiza CyberScore ni findings de seguridad.

## Segundo incremento: comparación longitudinal de snapshots

La ruta `GET /api/organizations/{slug}/assets/comparison` compara dos
instantáneas del mismo tenant a partir de `previousImportId` y
`currentImportId`. La verificación de tenant ocurre antes de leer los
datos de ambas instantáneas; el acceso a un ID externo devuelve MISSING.

El comparador lee como máximo 10.001 filas por snapshot y rechaza cualquier
truncamiento o discrepancia entre el contador del import y los datos
persistidos. No produce un informe parcial presentado como completo.

Las categorías de diferencias son NEW_ASSET, MISSING_FROM_EXPORT,
NEW_PRODUCT, PRODUCT_NOT_IN_EXPORT, OS_CHANGED, VERSION_CHANGED,
PLATFORM_CHANGED, ADVISORY_CHANGED, OBSERVATION_UPDATED y UNCHANGED.
Una observación puede producir varias categorías. Los agregados incluyen
todas las filas persistidas de ambas instantáneas; la lista de diferencias
se pagina y filtra. Se incluyen digests reproducibles para detectar
diferencias entre lecturas sin proclamar inmutabilidad criptográfica del
almacenamiento.

**Semántica conservadora:** la desaparición de una fila del segundo CSV
no demuestra que se haya eliminado un dispositivo o desinstalado un
producto, porque el inventario aportado puede ser parcial. Un cambio
de versión declarado no demuestra aplicación de parches; un cambio
de aviso CVE puede proceder de diferentes feeds o versiones. El estado
de cobertura se declara DECLARED_SCOPE_UNKNOWN.

## Segundo incremento: retención y borrado controlado

La ruta `GET /api/organizations/{slug}/assets/retention` ofrece un
informe administrativo acotado por página y umbrales: edad total del
snapshot y días desde su retirada. No modifica ningún dato ni activa
un scheduler.

La ruta `POST /api/organizations/{slug}/assets/retention` admite una
solicitud de borrado de un snapshot RETIRED. Exige ADMIN/OWNER,
identificador exacto repetido para confirmación, digest esperado
de 64 caracteres, motivo de al menos 20 caracteres, clave de
idempotencia y periodo mínimo de retención tras retirada.

La previsualización predeterminada `dryRun:true` no modifica registros.
La ejecución `dryRun:false` revalida organización, estado RETIRED,
digest, tiempo transcurrido y número esperado de observaciones dentro
de la misma transacción que elimina el snapshot y las filas relacionadas.
El modelo PostgreSQL tiene relación con `ON DELETE CASCADE`.
Se crea un AuditEvent con digest, motivo, número de filas y fecha;
el evento permanece aunque el snapshot y las observaciones de activo
desaparezcan. El reintento con la misma clave vuelve al evento previo
sin repetir el borrado. La reutilización de la clave con un comando
diferente genera conflicto.

**Limitaciones de cumplimiento:** el borrado afecta a la base de datos
activa. No acredita que los datos se hayan eliminado de backups,
exportaciones previas o sistemas de terceros. La edad mínima incluida
en el comando y la política diagnóstica de candidatos son decisiones
operativas configurables; no sustituyen criterios legales de conservación.
El borrado no modifica CyberScore ni hallazgos.

Las pruebas de este incremento cubren categorías de diferencia,
filtrado, límites, timestamps, hashes, condiciones de autorización,
retención mínima, vistas previas, idempotencia de borrado,
aislamiento entre organizaciones y transacciones PostgreSQL.

## Tercer incremento: evaluación conservadora de exports OSV

El workspace de Assets incluye un analizador de snapshots OSV aportados por
el operador. El contrato sigue la estructura `id`, `modified`,
`withdrawn`, `aliases`, `affected[].package`, `versions` y
`ranges` publicada por el proyecto OSV:
https://ossf.github.io/osv-schema/

**No se descarga ni se autentica un feed externo.** El sistema recibe
hasta 500 registros OSV estructurados en JSON, con `sourceLabel`,
`sourceVersion` y `retrievedAt`. Exige timestamps UTC válidos, paquetes
identificados por ecosistema y nombre, y rechaza duplicados. Los rangos
de versiones pueden declararse, pero no se interpretan automáticamente,
porque su semántica depende del ecosistema y del tipo de rango.

El operador debe facilitar vinculaciones explícitas
`inventoryProduct -> ecosystem + packageName` y, opcionalmente, PURL.
Se rechazan equivalencias duplicadas. Un mismo nombre de paquete de
ecosistemas diferentes no es intercambiable. La única correlación que
produce `EXACT_AFFECTED_VERSION` requiere una versión exacta del
inventario incluida literalmente en `affected[].versions` para la
identidad de paquete enlazada. Los registros retirados `withdrawn`
no generan coincidencias positivas. Los rangos no evaluados y los
nombres de producto sin asignar conservan un estado de incertidumbre.

Categorías explícitas del resultado:
- `EXACT_AFFECTED_VERSION`: posible asociación literal declarada.
- `NO_EXACT_VERSION_MATCH`: ninguna coincidencia exacta en el feed aportado;
  **no** significa que el producto esté libre de vulnerabilidades.
- `UNKNOWN_VERSION`: versión insuficiente, ausente o ambigua.
- `UNMAPPED_PRODUCT`: no existe equivalencia aprobada.
- `RANGES_UNEVALUATED`: hay rangos que no pueden resolverse con el
  motor conservador.
- `WITHDRAWN_RECORD`: solo aparecen registros retirados.

La API `POST /api/organizations/{slug}/assets/osv-candidates`
rechaza solicitudes superiores a 1 MiB, comprueba permisos de lectura
y la organización del inventario, verifica que el número de filas leídas
coincide con el snapshot importado y no ejecuta escrituras ni llamadas
de red. Devuelve un informe versionado, digest SHA-256, metadatos de
procedencia, recuentos para el conjunto completo y página de candidatos
acotada. Si la cobertura del inventario no puede confirmarse, se
rechaza la evaluación.

La interfaz permite cargar JSON y equivalencias de paquete,
previsualizar un ejemplo sintético, confirmar el significado limitado
de los resultados y consultar páginas y categorías. No crea findings,
no atribuye explotación real, no modifica CyberScore y no presenta
una coincidencia como verificación de parche o exposición.

Las pruebas cubren esquema, entradas inválidas, rangos sin evaluación,
aliases, retirada, identidad por ecosistema, PURL, igualdad de versión,
paginación, interpretaciones conservadoras, aislamiento PostgreSQL y
carácter read-only. Para usar fuentes oficiales de forma automática
queda pendiente incorporar verificación y autenticación del proveedor,
descarga controlada, versionado persistente y política de frescura del
feed; esta fase no promete esas funciones.

## Cuarto incremento: consulta oficial directa a OSV.dev

Se añade `POST /api/organizations/{slug}/assets/osv-official`, reservado
a ADMIN/OWNER. A diferencia del export JSON manual del bloque anterior,
este endpoint sí consulta el servicio remoto de OSV.dev desde el servidor,
pero solo cuando el operador autoriza expresamente el envío.

La API oficial documenta el contrato `POST https://api.osv.dev/v1/query`
para `package: {name, ecosystem}` y `version`, o para una PURL
sin versión y la versión independiente. La consulta OSV admite
paginación con `next_page_token` y el servidor declara que puede
aplicar coincidencia de versión aproximada:

https://google.github.io/osv.dev/post-v1-query/

Controles de la implementación:

- Destino HTTPS fijo `api.osv.dev/v1/query`, sin URLs aportadas por el
  cliente, sin redirecciones, sin credenciales y sin cookies.
- Los datos enviados se limitan a nombre de paquete, ecosistema,
  versión y, opcionalmente, PURL desprovista de versión.
- Se rechazan entradas arbitrarias, secuencias de control,
  rutas sospechosas y versiones indeterminadas.
- El administrador previsualiza por defecto sin red y debe consentir
  explícitamente la consulta.
- Deduplicación de parejas paquete/version entre filas del mismo
  snapshot para reducir peticiones innecesarias.
- Presupuesto acotado de paquetes (máximo 20), páginas (máximo 3),
  registros (máximo 100 por consulta), bytes recibidos por página
  y timeout.
- HTTP no-2xx, JSON inválido, exceso de tamaño, paginación ciclada
  y respuestas contradictorias se clasifican como fallos o cobertura
  truncada. No se presenta un fallo como ausencia de vulnerabilidades.
- En cada respuesta se conserva fuente, fecha de consulta, volumen,
  resultado, digest y advertencias de cobertura/frescura. No se crean
  hallazgos ni se modifica CyberScore.
- Se exige importación activa, tenant correcto, cobertura completa
  por número de filas y permisos adecuados.

La API de OSV **puede hacer fuzzy match de versiones**. Por eso el
resultado distingue las posibles asociaciones por enumeración literal
`affected.versions` de otros IDs que OSV comunica sin enumeración
literal, rangos no evaluados y avisos withdrawn. Una coincidencia,
incluso literal, no prueba exposición ni explotación real.

**Garantía de procedencia:** la aplicación contacta con el endpoint
oficial por HTTPS. Eso valida el destino de transporte bajo el sistema
de confianza TLS del servidor, pero **no constituye una firma
criptográfica del registro OSV**, una comprobación del origen primario
de la vulnerabilidad ni un estado certificable de parche.

**Alcance pendiente:** firma o validación externa de advisories,
persistencia de snapshots firmados del proveedor, trabajos recurrentes
programados, cache compartida y control de cuotas globales
inter-tenant, evaluación completa de rangos por ecosistema y
aceptación LIVE con red real. Los tests ejecutan respuestas HTTPS
simuladas mediante un fetch inyectado; el CI no certifica
disponibilidad o fidelidad de OSV.dev en producción.

## Quinto incremento: historial OSV duradero y versionado

Se incorpora el contrato `AssetOsvInspection` + `AssetOsvQueryRecord` de
Prisma/PostgreSQL, con la migración
`20261105123000_asset_osv_inspection_ledger`. Una inspección pertenece
siempre a una organización y un `AssetInventoryImport` concreto.
Cada paquete consultado tiene un registro propio con ecosistema,
nombre, versión, estado del proveedor, digest y referencias agrupadas.
El almacenamiento es inmutable desde la API; las filas no incluyen
identificadores de dispositivos ni credenciales, y las respuestas
HTTP crudas no se persisten.

`GET /api/organizations/{slug}/assets/osv-inspections` permite listar
inspecciones paginadas por import, estado y fecha, así como leer un
detalle específico con sus consultas registradas. MEMBER y AUDITOR
pueden leer dentro de su organización; los IDs externos se rechazan
sin revelar su existencia.

`POST /api/organizations/{slug}/assets/osv-inspections` acepta una
solicitud `{requestKey, inspection}` con parámetros equivalentes a la
consulta oficial, `dryRun:false` obligatorio, y tamaño máximo de
64 KiB. Requiere ADMIN/OWNER. El identificador de idempotencia
se valida y queda ligado al digest del comando y la organización.

Antes de contactar OSV se busca una ejecución existente con la misma
clave: si coincide, se devuelve exactamente el informe previamente
almacenado sin volver a llamar al proveedor; si difiere, se rechaza.
Las consultas de red ocurren fuera de la transacción PostgreSQL.
Después se revalida que el inventario siga activo y se guardan
atómicamente cabecera, consultas y AuditEvent. Una colisión única
de clave tras carreras se resuelve buscando el registro existente y
validando su digest, en lugar de considerar el segundo evento
automáticamente como un error 500.

La interfaz en `/organizations/{slug}/assets` ofrece
historial, filtros, páginas, lectura de informes y digests, además
de un procedimiento con preview sin red seguido de confirmación
explícita antes de consultar al proveedor y persistir.

**Interpretación:** `COMPLETE` únicamente se refiere a la
cobertura del plan de consultas OSV disponible en esa ejecución;
no equivale a cobertura del parque de dispositivos ni acredita
ausencia de vulnerabilidades. Los snapshots guardados son históricos
y sus datos pueden quedar obsoletos al cambiar los avisos.

Las pruebas cubren validación de comandos, digests, replays,
conflictos de claves, reportes atribuidos a otra organización,
resultados fuera del plan, alta transaccional real PostgreSQL,
lecturas dentro y fuera de tenant, auditoría y prohibición
de nuevas consultas tras retirar el inventario.

## Sexto incremento: frescura OSV, presupuesto orientativo y deltas de historial

`GET /api/organizations/{slug}/assets/refresh-readiness` analiza
las inspecciones registradas de un inventario para identificar
identidades de paquete/version pendientes de evaluación,
observaciones suficientemente recientes, respuestas incompletas
en periodo de enfriamiento, e inconsistencias temporales.

El plan admite políticas de frescura, cooldown tras error,
presupuesto diario de consultas, inspecciones por día y
límite de paquetes recomendados. El periodo de historial
es configurable, con límites de lectura y paginación.
El resumen cuenta todo el histórico analizado; las filas
detalladas se devuelven por páginas.

**Los presupuestos son diagnósticos, no reservas atómicas.**
El cálculo usa las inspecciones del día UTC disponibles en
PostgreSQL. Dos operadores pueden leer un presupuesto a la
vez; por eso este incremento no automatiza los fetch ni
afirma aplicar un límite físico al proveedor. Para programar
ejecuciones se necesita una reserva transaccional de cuotas
y un worker autorizado, además de una política de
consentimiento y reintentos.

`GET /api/organizations/{slug}/assets/osv-history-delta`
compara dos inspecciones del mismo inventario y tenant,
con orden temporal comprobado. Solo compara paquetes
idénticos en ecosistema, nombre y versión, sin correlación
difusa ni suposiciones sobre hardware.

Las diferencias identifican IDs literales añadidos,
IDs que ya no figuran, IDs aproximados del proveedor,
cambios de registros withdrawn, rangos sin resolver
y cambios de estado de completitud. Los recuentos se
calculan sobre todos los paquetes comparables, y cada
cambio recibe una huella SHA-256. Los paquetes que no
existen en ambas inspecciones se excluyen y provocan
informe parcial. No se interpreta que un aviso ausente
haya sido solucionado o que un equipo esté parcheado.

La interfaz `asset-osv-refresh-diagnostics.tsx` muestra
controles de políticas, estado, paquetes recomendados,
presupuesto orientativo, deltas históricos y advertencias.
Se conserva el aislamiento por organización y el carácter
read-only tanto en los servicios como en las rutas.

Se añaden pruebas unitarias de validación, cooldown,
frescura, agregaciones de presupuesto y diferencias
conservadoras, además de pruebas PostgreSQL de
lectura por tenant, filtros, comparaciones, consistencia
de contadores y ausencia de escrituras.

**Fuera de alcance:** scheduler periódico, cuota global
concurrente garantizada, eliminación de avisos con
fines de cumplimiento, notificaciones por cambio y
atestación de remediaciones mediante agentes o
fuentes autorizadas de endpoint.

## Séptimo incremento: cuotas atómicas y reservas OSV con recuperación auditada

Las llamadas remotas del servicio oficial OSV ahora pasan por
`assets-osv-atomic-quota.ts`, integrado en `inspectOfficialOsv`.
El contrato define un presupuesto real, por organización y día
UTC, predeterminado a 20 inspecciones y 200 páginas HTTP
reservadas por día. Los máximos operativos son fijos en servidor
y no pueden ampliarse por parámetros de la petición pública.
Cada ejecución reserva antes de tocar la red el peor caso
`paquetesSeleccionados × maxPagesPerPackage`, con límite de 60
páginas reservadas por inspección. El preview `dryRun:true`
no reserva ni contacta al proveedor.

La migración
`20261109113000_osv_atomic_quota_reservations` introduce
`AssetOsvQuotaDay` y `AssetOsvQuotaReservation`. El contador
diario posee una clave única `(organizationId, utcDay)`;
las reservas tienen clave única por organización y requestKey.
El servicio incrementa ambos contadores mediante una única
operación condicional `UPDATE ... WHERE` de PostgreSQL
dentro de una transacción. Si no hay presupuesto, la transacción
no crea una reserva y se rechaza la consulta antes del fetch.

El límite se aplica tanto a la API de consulta directa como
a la API de inspecciones persistidas. La ruta del historial
utiliza una clave de reserva vinculada a la idempotencia del
comando, para que una ejecución concurrente con la misma
identidad no pueda realizar un segundo fetch.

Después del trabajo, la reserva pasa a `FINISHED` o `FAILED`,
con el número de páginas comunicado por el cliente. La cuota
reservada **no se devuelve**, ni siquiera ante fallo; eso
evita afirmar que un paquete HTTP nunca alcanzó al proveedor.
Una interrupción del proceso puede dejar una reserva abierta.

Las nuevas rutas administrativas:
- `GET /api/organizations/{slug}/assets/osv-quota`:
  presupuesto, consumo atómico, reservas y estados sin
  exponer datos de otras organizaciones.
- `GET /api/organizations/{slug}/assets/osv-quota-recovery`:
  previsualización read-only de reservas sin liquidar y
  evaluación de antigüedad mínima.
- `POST /api/organizations/{slug}/assets/osv-quota-recovery`:
  clasificación manual de un resultado desconocido como
  `UNKNOWN`, con ID confirmado dos veces, digest esperado,
  explicación suficientemente detallada, edad mínima y
  AuditEvent transaccional.

La recuperación no devuelve cuota, no vuelve a consultar
OSV ni cambia evidencias. Una clasificación `UNKNOWN`
repetida se trata idempotentemente y no duplica el AuditEvent.
No se permite reescribir los estados terminales `FINISHED`
o `FAILED`.

La interfaz de Assets ofrece contadores de cuota,
diagnóstico de reservas y proceso de revisión asistido
con confirmación explícita y huellas verificables.

Las pruebas PostgreSQL ejercitan concurrencia con dos
reservas, rechazo tras agotamiento, bloqueo del fetch real
del servicio, replay, separación de organizaciones,
aislamiento entre días UTC, liquidación sin reembolso,
recuperación de una reserva antigua y auditoría.

**Limitaciones explícitas:** el contador limita solo las
consultas realizadas a través de este servicio y base de
datos compartida; otros clientes que utilicen OSV.dev no
consumen estas reservas. Una reserva temporal `RESERVED`
no garantiza que no se hayan enviado páginas antes de una
caída del proceso. No se habilita aún un scheduler,
automatización sin consentimiento, circuit breaker
compartido ni distribución externa de cuotas.

## Octavo incremento: renovación controlada de inspecciones OSV

La nueva ruta `POST /api/organizations/{slug}/assets/osv-renewal`
implementa dos operaciones explícitas: `dryRun:true` crea
un informe de elegibilidad sin consultar al proveedor ni
reservar cuota, y `dryRun:false` ejecuta una renovación
aprobada cuyo digest corresponda al plan presentado.

El contrato `assets-osv-renewal.ts` exige seleccionar una
inspección histórica del mismo tenant y snapshot activo,
proporcionar nuevamente las equivalencias de paquetes
aprobadas y conservar una clave de idempotencia. Se valida
el recuento integral de filas de inventario y la cobertura
de consultas de la inspección histórica.

La aprobación queda ligada por SHA-256 al snapshot, inspección
de origen, digest del informe previo, clave idempotente, versión
y ecosistema de cada paquete, límites, política de frescura
y autorizaciones adicionales. El instante de la vista previa
y los contadores variables de cuota se recalculan en la
ejecución; la previsualización no reserva capacidad.

**Frescura efectiva:** la evaluación busca las consultas más
recientes registradas en todas las inspecciones del mismo
inventario, no solo en la fuente histórica seleccionada.
Esto impide eludir el intervalo de frescura seleccionando
deliberadamente una inspección antigua. También se respeta
el cooldown de las respuestas fallidas. Si hay más de
10.000 registros históricos en esa evaluación, se bloquea
con cobertura desconocida.

Los paquetes que no figuraban en la inspección anterior
requieren autorización adicional `allowNewPackages`; las
filas de inventario sin equivalencia o con versión ambigua
requieren `allowIncompleteInventory`. Un paquete reciente,
un error durante cooldown, una fecha futura, consulta omitida
por presupuesto o agotamiento de cuota impiden ejecutar.
El informe enumera cada bloqueo para facilitar revisión.

La ejecución utiliza el ledger existente, conserva el
resultado histórico e intenta calcular el delta de avisos
frente a la inspección anterior. Si falla una comparación
posterior al guardado, el informe ya almacenado conserva su
identidad; la aplicación no repite consultas de red
simplemente para producir un delta.

La UI `asset-osv-renewal-workspace.tsx` permite seleccionar
inventario e inspección, cargar mapeos revisados desde JSON
local limitado, configurar frescura y cooldown, ver todas
las decisiones y advertencias, autorizar aparte el envío
a OSV.dev y revisar el informe resultante.

**Este bloque no activa un scheduler automático.** Las
renovaciones se inician expresamente por un administrador,
consume cuota atómica y mantienen su estado en el ledger
de evidencias declaradas. Las diferencias OSV no acreditan
parcheado, seguridad del endpoint, reducción del riesgo,
explotación ni resultado del CyberScore.

## Noveno incremento: políticas recurrentes con consentimiento y reclamación única

Se implementa la infraestructura persistente de programaciones OSV
con una separación deliberada entre *definir*, *autorizar*,
*previsualizar* y *ejecutar* una franja vencida.

Los nuevos modelos PostgreSQL `AssetOsvRenewalSchedule` y
`AssetOsvRenewalRun` están en la migración
`20261110100000_osv_renewal_schedule`. Cada definición
registra organización, snapshot, inspección fuente, equivalencias
de paquetes, frecuencia, configuración de frescura, permisos
específicos, consentimiento versionado, siguiente vencimiento,
revision y auditoría. Nace **desactivada**, sin consentimiento.
Se incluyen restricciones SQL de frecuencia, consentimiento
y estados y una clave única `(scheduleId, slotAt)`.

`apps/web/lib/assets-osv-renewal-schedules.ts` ofrece creación,
listado acotado, activación explícita vinculada por SHA-256 al
contenido exacto del plan y organización, desactivación
inmediata para futuros slots, reconfiguración solo si está
deshabilitado, lectura de históricos, previsualización
sin red, y despacho único de una franja vencida.

La ruta `/api/organizations/{slug}/assets/osv-schedules` utiliza
`GET` (lista/preview/history), `POST` (crear desactivada),
`PATCH` (activar/revocar/reconfigurar mediante revisión
optimista) y `PUT` (despacho de un único vencimiento
con confirmación del administrador). Todas las operaciones
están limitadas por tenant y requieren ADMIN/OWNER.

La ejecución crea en una transacción una reclamación
duradera `CLAIMED`, avanza al siguiente slot futuro
sin generar ráfagas retrospectivas y registra un AuditEvent.
El control `revision` junto con `UPDATE ... WHERE` y el
índice único de slot permite **a lo sumo un despacho por
franja** aunque dos operadores ejecuten simultáneamente.
Después vuelve a revisar frescura, consulta anterior,
cuota y aprobación. Solo el plan elegible pasa a la
renovación manual ya existente, que reserva cuota atómica
antes de consultar OSV.dev. Se registra el resultado
`COMPLETE`, `BLOCKED` o `FAILED` y una auditoría
independiente. No se reintenta automáticamente un
resultado fallido.

Se ofrece una nueva interfaz `AssetOsvScheduleWorkspace`
para preparar políticas, seleccionar origen e inventario,
autorizar la activación, revisar presupuestos y bloqueos,
despachar manualmente una franja y consultar el diario
de resultados.

**Límite operativo esencial:** no se instala un cron,
worker de barrido autónomo ni tarea recurrente del sistema.
La planificación persiste y se calculan vencimientos,
pero la ejecución requiere una petición administrativa
explícita. Esta elección conserva el consentimiento y
evita activar una fuente externa sin un control de
despliegue verificado. Antes de habilitar un scheduler
real se necesitan identidad de servicio limitada,
monitoreo/alertas, recuperación auditada de claims
abandonados, política de despliegue y aceptación LIVE
de OSV.dev.

Los tests cubren parser y seguridad de consentimiento,
cálculo de franjas sin catch-up descontrolado, identidad
idempotente de slot, permisos, aislamiento de tenant,
creación desactivada, previsualización sin escrituras,
revisión optimista, dos despachos PostgreSQL concurrentes,
revocación, resultado persistido y AuditEvent.

Ni la definición, ni el despacho, ni la variación de IDs
OSV acreditan seguridad, vulnerabilidad explotable o
remediación verificada en un dispositivo.

## Décimo incremento: recuperación de claims y preparación de worker seguro

`assets-osv-run-recovery.ts` implementa la detección de
`AssetOsvRenewalRun` atascados en `CLAIMED`, con filtros
por organización, antigüedad tras `claimExpiresAt`, límite
de resultados y lectura correlacionada de la posible
reserva de cuota y de la inspección ya persistida.

La previsualización es **solo lectura** y no ejecuta
consultas a OSV.dev. Los resultados muestran la franja,
el vencimiento del claim, la idempotencia determinista,
el digest del comando, el estado de cuota y la posible
inspección asociada. Un run antiguo puede tener su
informe persistido aunque el scheduler nunca haya
terminado de registrar el resultado.

La clasificación `UNKNOWN` exige rol ADMIN/OWNER,
el ID exacto confirmado dos veces, digest esperado,
expiración efectiva, demora mínima de investigación,
motivo explícito y aceptación del resultado remoto
desconocido. Utiliza `updateMany` condicional dentro
de la misma transacción que crea `AuditEvent`, con
protección ante carreras y cambio terminal concurrente.
Las repeticiones ya clasificadas no crean otra auditoría.

**UNKNOWN nunca significa que el proveedor no recibió
la petición.** No se liberan franjas únicas, no se
reembolsan cuotas, no se vuelve a consultar OSV.dev
y no se modifica el estado de un dispositivo.
El resultado se conserva para investigación humana.

`assets-osv-worker-readiness.ts` ofrece un informe
acotado por tenant con número de calendarios,
consentimientos, vencimientos, claims atascados,
cuotas sin liquidar, estados desconocidos, capacidad
atómica restante y condiciones bloqueantes. Vuelve
a calcular el digest canónico de cada configuración
para evitar tratar una cadena SHA bien formada como
autorización válida.

Se propone asimismo un contrato declarativo de
identidad de servicio con permisos mínimos:
leer vencimientos, reclamar una franja, registrar
resultado y reservar cuota. No concede permisos
para activar calendarios, ampliar cuotas, cambiar
hallazgos ni modificar CyberScore. Requiere
identidad real auditada, firma de despacho, límites
por tenant y aceptación del despliegue.

Las rutas nuevas
`GET/POST /api/organizations/{slug}/assets/osv-run-recovery`
y `GET /api/organizations/{slug}/assets/osv-worker-readiness`
requieren autorización administrativa, validan
parámetros y tamaño y no permiten consultar datos
de organizaciones ajenas.

El panel `asset-osv-worker-operations.tsx` permite
revisar incidentes y su procedencia, confirmar
recuperaciones y consultar bloqueos para un futuro
worker. Se añaden tests unitarios de validación,
frescura y privilegios, y PostgreSQL de carreras,
idempotencia, auditoría, cuotas y RBAC.

**NO se ha creado una identidad de servicio real, ni
un trigger cron, worker autónomo o secreto de despliegue.**
`automationReady:false` y
`externalWorkerInstalled:false` son explícitos.
Se requiere aceptación operativa y LIVE del proveedor
antes de autorizar tráfico recurrente automático.

## Undécimo incremento: despacho de servicio firmado, aislamiento y telemetría

El endpoint interno `POST /api/internal/osv/signed-dispatch` se
implementa **desactivado por defecto**. Solo existe capacidad
de despacho si el operador configura explícitamente
`CYBERPILOT_OSV_SIGNED_DISPATCH_ENABLED=true` y un JSON de
claves por organización en `CYBERPILOT_OSV_DISPATCH_KEYS`
administrado por el gestor de secretos de su entorno. La
configuración contiene entradas con `id`, `organizationId`
y `secretHex` (32 bytes aleatorios representados como
64 caracteres hexadecimales). No se incluye ninguna
credencial real en el repositorio, la migración o la UI.

Cada petición usa el contrato
`cyberpilot.assets.osv.signed-dispatch.v1` con el ID y
slug de organización, ID de agenda, revisión esperada,
`issuedAt`, `expiresAt`, nonce único y autorización
expresa de despacho. Se limita a 4 KiB y al método POST
JSON. Se requieren las cabeceras `x-cyberpilot-osv-key-id`
y `x-cyberpilot-osv-signature`; esta última contiene el
HMAC-SHA256 hexadecimal, calculado sobre el texto
canónico que incluye versión, método, ruta y todos los
atributos relevantes. La comparación de firmas se realiza
con `timingSafeEqual` después de comprobar la longitud.

Las firmas caducan en como máximo **120 segundos** y se
acepta un desfase máximo de reloj de 30 segundos. Las
claves están limitadas a una organización. Una firma
correcta no autoriza cambiar agendas, consentimientos,
cuotas, hallazgos o CyberScore: solo reclamar una agenda
*ya habilitada*, consentida, vencida y con la revisión
vigente. El camino de ejecución conserva los controles
de cuota, frescura, auditoría y franjas únicas existentes.

La migración `20261110150000_osv_signed_dispatch_nonces`
introduce `AssetOsvDispatchNonce`, con unicidad por
`(organizationId, nonceDigest)`. Se consume el nonce
dentro de una transacción PostgreSQL, junto con un
`AuditEvent` de tipo `SYSTEM`. Se persisten únicamente
hashes de nonce y petición, ID de clave y horario;
**no se almacenan la firma ni el secreto**. Un nonce
consumido no se reutiliza, ni aunque falle después la
consulta a OSV.dev. El resultado de inspecciones
creadas desde esta vía se atribuye asimismo al actor
`SYSTEM` y no a un usuario humano ficticio.

`assets-osv-dispatch-observability.ts` y
`GET /api/organizations/{slug}/assets/osv-dispatch-observability`
aportan diagnósticos de solo lectura y tenant-scoped:
claves configuradas (únicamente IDs), nonces aceptados,
resultados de agenda, claims abiertos, fallos, resultados
indeterminados y umbrales de alerta. La correlación
entre una firma y un resultado se basa en proximidad
temporal y se declara expresamente **orientativa**.
El panel administrativo muestra los registros, problemas
y posibles acciones sin ejecutar reintentos.

Las pruebas incorporan validación estricta de claves,
HMAC, firma ligada a organización y franja, timestamps,
límite de caducidad, gestión de errores, controles
PostgreSQL de nonce único, atribución SYSTEM, RBAC,
aislamiento multitenant, consentimiento y observabilidad.

**Limitaciones pendientes:** no hay un emisor desplegado
de peticiones firmadas, barrido cron, alerta enviada a
correo/pager, provisión real de secretos ni despliegue
operativo aceptado. La interfaz expone alertas bajo
demanda pero no las entrega proactivamente. El operador
debe configurar HTTPS, key rotation, monitorización,
gestión de incidentes y aceptación LIVE antes de
permitir cualquier tráfico externo autónomo.

Las pruebas CI con proveedores inyectados verifican
el código sin depender de tenants de Google Workspace,
Microsoft 365 u otros proveedores externos.

## Duodécimo incremento: incidentes persistentes y revisión operativa OSV

El registro de incidentes del despachador OSV se implementa
con `AssetOsvDispatchAlert` y la migración
`20261110163000_osv_dispatch_alert_triage`. Cada registro
contiene organización, código, sujeto único, severidad,
estado, revisión, primera y última observación, digest
canónico de evidencia, número de observaciones, motivos
y responsables humanos de reconocimiento y cierre.
PostgreSQL obliga la unicidad
`(organizationId,code,subjectKey)` e incorpora
checks de severidad, estado y revisión positiva.

El servicio `assets-osv-dispatch-alerts.ts` convierte
los diagnósticos locales de `assets-osv-dispatch-observability`
en observaciones con huellas estables. Los avisos
generales del tenant tienen sujeto `tenant`; los
avisos de solicitudes firmadas se separan por el
SHA-256 de la petición, nunca por secreto o firma.

**El escaneo se inicia manualmente**, no mediante cron.
No contacta OSV.dev, ni crea peticiones externas,
ni libera cuotas. Se limita a historiales completos
y acotados; si el diagnóstico está truncado, rechaza
persistir inferencias parciales. Evidencia idéntica
no duplica eventos ni incrementa los contadores.
Si la evidencia cambia, se actualiza el incidente
con CAS de revisión y AuditEvent. Un incidente
reconocido retiene su reconocimiento; uno resuelto
se reabre ante evidencia distinta. La ausencia de
una alerta en el escaneo no certifica que desapareció
el problema.

El ciclo de revisión del operador es:
`OPEN → ACKNOWLEDGED → RESOLVED`, con reapertura
manual `RESOLVED → OPEN` cuando corresponde.
Cada transición requiere rol ADMIN/OWNER,
revisión esperada, digest exacto de evidencia,
motivo de 20-500 caracteres y registro de auditoría
en la misma transacción que la modificación.
Reconocer no significa resolver, y resolver no
implica remediación de CVE ni seguridad de endpoints.

La API
`/api/organizations/{slug}/assets/osv-dispatch-alerts`
implementa `GET` (lista paginada con filtros),
`POST` (escaneo diagnóstico local) y
`PATCH` (transición de revisión).
Los controles comprueban RBAC y aislamiento
por organización, tamaños acotados, cuerpos JSON
y revisión de escritura optimista.

La interfaz `AssetOsvDispatchIncidentWorkspace`
permite evaluar señales, comparar digests,
revisar evidencias, reconocer, documentar
resoluciones, reabrir incidentes y navegar
históricos sin enviar consultas OSV.
Se incluyen pruebas unitarias de parser,
huellas, transiciones y cobertura, junto con
pruebas PostgreSQL de aislamiento tenant,
deduplicación, auditoría, revisión CAS,
preservación de reconocimientos y reapertura
ante observaciones nuevas.

**Limitaciones:** no hay envío automático de
alertas por correo/pager, scheduler autónomo
ni aceptación LIVE de un proveedor externo.
El registro de incidentes describe operaciones
de la aplicación, no explotación, protección,
aplicación de parches ni CyberScore.

## Decimotercer incremento: ventanas de rotación de credenciales HMAC

La configuración del dispatcher acepta opcionalmente para cada
credencial de organización `notBefore`, `notAfter` y
`state` (`ACTIVE`, `RETIRING` o `REVOKED`).
Las entradas anteriores, que contenían exclusivamente
`id`, `organizationId` y `secretHex`, siguen siendo
válidas para mantener compatibilidad operativa.
Todas las fechas admitidas se normalizan a ISO 8601 UTC
con milisegundos; una ventana invertida es inválida.

`verifySignedDispatch` exige, además de la firma
HMAC-SHA256 y el aislamiento tenant ya existentes,
que la clave sea admisible tanto en la fecha
`issuedAt` como en el momento de verificación.
Una clave `REVOKED` rechaza peticiones incluso si
su firma es criptográficamente correcta. Una clave
`RETIRING` sin límite `notAfter` se rechaza
conservadoramente. Después del cutover, la clave
retirada no recibe un período de gracia implícito.
La unicidad del nonce persiste independientemente
del estado o rotación de la clave.

`assets-osv-key-rotation.ts` implementa evaluaciones
por organización, sin contactos externos ni escritura
de secretos, de ventanas de activación y expiración,
solapamiento, cantidad máxima de claves concurrentes,
uso de material criptográfico distinto, reclamaciones
de scheduler sin resolver, reservas de cuota abiertas
y peticiones firmadas recientemente.
El plan de rotación incluye motivos bloqueantes,
un digest SHA-256 de configuración **sin secretos**,
estados antes/después y un itinerario PREPARE,
VERIFY, OVERLAP, RETIRE, REVOKE con comprobaciones
de operador y consideraciones de reversión.

La API
`GET/POST /api/organizations/{slug}/assets/osv-key-rotation`
permite consultar solo IDs/ventanas y previsualizar
la propuesta; exige rol administrativo y prohíbe
leer el material de firma. Un reemplazo todavía
no instalado se representa mediante una clave
**sintética exclusivamente en memoria**, se marca
explícitamente como no apto para aprobación y nunca
se presenta como credencial disponible.

El panel `AssetOsvKeyRotationWorkspace` expone
las claves por ID, estados, posibles solapamientos,
condiciones de bloqueo y plan de transición.
La aplicación no modifica variables de entorno,
secrets managers, credenciales reales ni ajustes
de despliegue. La configuración y activación deben
seguir un procedimiento de operaciones independiente.

La batería de pruebas cubre validez temporal,
rechazo inmediato de revocadas, incompatibilidad
de claves de otros tenants, límites de solapamiento,
detección de material reutilizado, bloqueo por
claims/quota pendientes, reportes sin secretos
y aceptación PostgreSQL de lectura multitenant
sin consultas a OSV.dev.

**Pendiente de aceptación:** rotación real de
credenciales en un entorno de despliegue con
gestor de secretos, gestión multi-réplica, rollback
y aceptación LIVE. La rotación declarada aquí
no instala scheduler, activa tráfico a proveedores,
ni demuestra seguridad de endpoints o remediación.

## Ronda doble CC — preflight firmado y reconciliación forense sin tenants externos

### Incremento 1 — preflight de admisión

`assets-osv-dispatch-preflight.ts` y
`GET/POST/PUT /api/organizations/{slug}/assets/osv-dispatch-preflight`
implementan un preflight **solo lectura** para administradores de
CyberPilot. Comprueba autorización de la agenda, digest canónico del
consentimiento, existencia de inventario COMMITTED e inspección fuente
COMPLETE, vencimiento permitido, intervalos atrasados, claims abiertos,
reservas de cuota, incidentes críticos, saldo diario de presupuesto y
existencia de credencial HMAC habilitada y vinculada a la organización.

Cada condición produce `PASS`, `WARN` o `BLOCK`,
con evidencia local y separación de condiciones obligatorias y
recomendaciones. Los filtros se validan y los conjuntos de agendas
se limitan. Un informe se identifica mediante SHA-256 del
contenido, pero este hash por sí solo no demuestra autenticidad
externa, autoriza despachos ni verifica el proveedor.

El desafío HMAC generado bajo petición de administrador prueba,
en memoria, una firma sintética válida y las denegaciones de
firma modificada, otro tenant y petición caducada. No envía
ninguna solicitud HTTP de despacho, no consume nonce,
no reserva cuota, no modifica una agenda y no instala cron.
La admisión real **repite todos los controles** en la frontera
del despacho; el preflight no es una reserva ni una autorización.

El panel `AssetOsvDispatchPreflightWorkspace` muestra
condiciones por agenda, blockers, controles de presupuesto,
ventanas temporales y el resultado del desafío sin secretos.

### Incremento 2 — línea de evidencia y verificación

`assets-osv-dispatch-forensics.ts` reconstruye un grafo
local y tenant-scoped de peticiones firmadas aceptadas,
claims persistentes, reservas de cuota, inspecciones
OSV y eventos de auditoría. Las relaciones
`EXACT_INSPECTION`, `EXACT_REQUEST_KEY` y
`EXACT_AUDIT_RESOURCE` se distinguen expresamente
de `TIME_ADJACENT_ONLY`, que es una coincidencia
temporal orientativa y **no prueba causalidad**.

El analizador detecta claims estancados, resultados
UNKNOWN, inspecciones ausentes de la ventana, recuentos
imposibles, cuotas sin liquidar, peticiones sin
claim observable y asociaciones ambiguas.
No transforma la ausencia de registros en una afirmación
de que OSV.dev no ha recibido una consulta.
El informe está limitado por ventana, tamaño y
colecciones; si la política requiere completitud,
se rechaza una consulta truncada en vez de
presentarla como cobertura suficiente.

`assets-osv-forensic-verification.ts` comprueba los
hashes SHA-256 de nodos y reporte, integridad
de referencias, conteos, orden canónico y
ausencia de efectos externos declarados.
Estos fingerprints son controles de integridad
local, **no firmas de origen**.
`GET/POST /api/organizations/{slug}/assets/osv-dispatch-forensics`
incorpora el veredicto de verificación en la respuesta.

El panel `AssetOsvDispatchForensicsWorkspace`
permite elegir ventanas, fuentes, límites,
filtrar anomalías, distinguir aristas exactas
de heurísticas, examinar evidencias y copiar un
JSON local. El JSON contiene identificadores
operativos; debe circular únicamente por
canales autorizados de respuesta a incidentes.

Se añaden pruebas unitarias y PostgreSQL de
digest, relaciones, anomalías, RBAC, aislamiento
entre organizaciones, ventanas y lectura sin efectos
secundarios. Ninguno de estos mecanismos
requiere tenants Google Workspace/Microsoft 365
ni credenciales LIVE de OSV.dev.

**Límites de aceptación:** no existe scheduler
autónomo, monitor de eventos recurrente ni
validación real del proveedor. Las pruebas
no acreditan remediación, exposición efectiva,
explotabilidad ni seguridad de un dispositivo,
y no modifican CyberScore ni findings.

## Ronda doble CC: guías trazables y seguimiento humano

### C1 — Orientaciones a partir de evidencia persistida

El motor assets-action-guidance.ts transforma un inventario CSV
COMMITTED y una inspección OSV almacenada del mismo tenant en propuestas
de investigación por activo y producto. La API POST
/api/organizations/{slug}/assets/action-guidance exige los dos
identificadores y un mapeo explícito producto-paquete. El servicio
assets-action-guidance-service.ts verifica que la inspección pertenece
al inventario solicitado, compara los contadores de PostgreSQL con
los datos íntegros y rechaza colecciones truncadas.

Las categorías son REVIEW_POSSIBLE_ADVISORY,
REVIEW_PROVIDER_UNCERTAINTY, REVIEW_SOURCE_INTEGRITY,
REVIEW_MISSING_MAPPING, REVIEW_UNKNOWN_VERSION,
REVIEW_STALE_OBSERVATION y NO_POSITIVE_MATCH_IN_SCOPED_INSPECTION.
La igualdad exacta de paquete y versión con la respuesta OSV guardada
permite proponer revisión, NO constatar exposición del endpoint.
Los IDs withdrawn, unresolved y provider-only se conservan por
separado; las respuestas incompletas y versiones ambiguas no se
presentan como ausencia de riesgo.

Cada candidato incluye la procedencia, digests, categoría,
justificación, checklist de acciones humanas y SHA-256 estable.
El informe se pagina y filtra sin presentar cobertura parcial como
completa. AssetActionGuidanceWorkspace ofrece exportación local,
revisión de fuentes y limitaciones. La evaluación no consulta
proveedores, no escribe findings ni modifica CyberScore.

### C2 — Casos persistentes de revisión con checklist y auditoría

AssetAdviceCase y AssetAdviceCaseStep registran trabajo humano
sobre candidatos, separados de SecurityFinding y Remediation.
La migración 20261110181000_asset_advice_cases añade unicidad por
organización/inspección/activo/producto, revisiones e índices.
La API GET/POST/PATCH/PUT
/api/organizations/{slug}/assets/action-cases admite consulta
paginada, apertura contra el fingerprint recomputado en servidor,
transición CAS y actualización auditada de pasos. Mutaciones
solo ADMIN/OWNER; lecturas limitadas a la organización.

El ciclo OPEN -> IN_REVIEW -> WORK_COMPLETED admite DISMISSED
documentado y REOPEN. WORK_COMPLETED requiere que todos los
pasos humanos estén DONE y documentados. Los eventos de auditoría
se escriben en la misma transacción que las mutaciones; una
apertura repetida con idéntica evidencia no duplica casos.
AssetActionCaseWorkspace expone casos, filtros, checklists,
notas y decisiones.

DONE y WORK_COMPLETED acreditan solamente trabajo humano
documentado; NO prueban aplicación de parches, exposición,
protección o remediación. Las decisiones no afectan CyberScore,
SecurityFinding, Remediation, cuotas OSV ni inspecciones guardadas.

### Aceptación

Se incorporan pruebas unitarias de categorías, integridad,
idempotencia, transiciones y permisos, además de integración
PostgreSQL de aislamiento tenant, apertura, progreso, auditoría,
reapertura y ausencia de mutaciones de hallazgos.
El desarrollo y la aceptación offline no necesitan tenants de
Google Workspace ni Microsoft 365 ni consultas LIVE de OSV.dev.
Pendiente aceptación manual representativa, política de retención
y las validaciones externas que sí requieren credenciales reales.

## Ronda doble CC: aceptación de producto y preparación de privacidad (10/11/2026)

### C1 — Aceptación offline trazable y sin terceros

El motor assets-offline-acceptance.ts evalúa el recorrido completo entre
inventario CSV declarado, inspección OSV guardada, candidaturas,
casos de revisión humana, pasos, procedencia y auditoría. No realiza
ninguna consulta a OSV.dev ni contactos con tenants externos.

Se introducen condiciones explícitas de bloqueo o advertencia para:
integridad de todos los registros del inventario, completitud del
proveedor, cobertura del mapeo producto-paquete independiente de la
exactitud de la versión, no elevación del no-match a seguridad,
reconciliación de digests, unicidad de casos, estados de revisión,
checklists y auditoría de apertura. Cada puerta de aceptación explica
sus datos, recursos afectados y límites.

El servicio assets-offline-acceptance-service.ts exige ADMIN/OWNER,
asocia por organizationId el inventario y su inspección, lee todos
los casos hasta un límite configurado y busca auditorías específicas
de apertura. Un conjunto truncado provoca CONFLICT. No hay
mutaciones de base de datos, modificaciones de CyberScore ni
cambios del ciclo de vida de SecurityFinding.

assets-offline-acceptance-verification.ts comprueba, de manera
independiente, el digest SHA-256 del informe, la presencia de todas
las condiciones obligatorias, conteos, unicidad, origen y ausencia
de efectos externos. No es autenticación criptográfica del productor.
La API POST /api/organizations/{slug}/assets/offline-acceptance
rechaza informes que fallen la verificación estructural.
AssetOfflineAcceptanceWorkspace ofrece una consola de aceptación
local con explicación por caso, filtros y exportación JSON.

Incluso cuando los checks de este motor no bloquean,
manualAcceptanceStillRequired sigue siendo true. Un resultado
ELIGIBLE no equivale a una aprobación operativa ni autoriza fusión.

### C2 — Preparación de retención, privacidad y borrado controlado

assets-privacy-readiness.ts y assets-privacy-readiness-service.ts
inspeccionan toda la colección acotada de snapshots de la
organización y generan una evaluación de tratamiento de datos
potencialmente personales. Agrupan registros por snapshot
para medir hostnames, ownerHash, inspecciones históricas, casos
humanos, schedules y auditoría relacionada.

Los hashes de propietario son seudonimización, no
anonimización. Los hostnames pueden identificar personas.
La edad de los snapshots, los casos no resueltos y la
persistencia de evidencia se consideran señales de revisión;
ninguna señal establece por sí misma base legal, tratamiento
adecuado o eliminación de copias.

Se implementan controles sobre retención, integridad del
inventario, antigüedad, PII, datos históricos, trazabilidad
de auditoría, dependencias de borrado y backups. El sistema
no acepta que la desactivación de un control de revisión
equivalga a una aprobación. Se presenta el procedimiento
CLASSIFY, APPROVE, RETIRE, VERIFY, PURGE, BACKUP_REVIEW, CLOSE,
cada etapa con revisión humana y evidencia esperada.

La API POST /api/organizations/{slug}/assets/privacy-readiness
requiere ADMIN/OWNER y límites de tamaño; no realiza cambios.
El panel AssetPrivacyReadinessWorkspace permite configurar
umbrales, revisar evidencia por importación, identificar
dependencias y exportar la evaluación. La eliminación real
requiere la operación de purge separada, autorizada y
auditable, que no se invoca desde estas herramientas.

La propiedad backupDeletionVerified es siempre false:
una operación PostgreSQL no demuestra eliminación de
copias de seguridad, exportaciones o réplicas externas.
No se emite aprobación legal automática.

### Pruebas y aceptación

Los tests cubren estados completos e incompletos, mapeos
faltantes incluso con versiones UNKNOWN, fingerprints
inconsistentes, revisión sin auditoría, casos completados
con pasos pendientes, fuentes de otro tenant, límites
de evaluación y políticas explícitas.

La integración PostgreSQL comprueba lectura aislada,
bloqueo previo a revisar un candidato OSV, casos auditados,
ausencia de escrituras durante la evaluación y señales
seudonimizadas sin revelar nombres de host u owner originales.

**Pendientes reales:** ejecución manual documentada
de escenarios de aceptación representativos, aprobación
de política de conservación y privacidad por el operador,
validación de eliminación/retención de backups y las
integraciones LIVE todavía excluidas de esta fase
offline. La fusión del PR #211 permanece sujeta a
la aceptación de producto y a todos los workflows.


## Registro de aceptación humana offline (AssetReleaseReview, PR #211)

La ruta administrativa `/api/organizations/[slug]/assets/release-reviews`
implementa lectura paginada (`GET`), apertura `PENDING` (`POST`) y transición
con revisión CAS (`PATCH`). Cada decisión se vincula al tenant y usuario
autenticados; no se permite especificar `organizationId` ni `actorUserId` desde
el cuerpo de la petición. Las operaciones requieren rol ADMIN u OWNER, incluyen
límites de entrada y devuelven `Cache-Control: private, no-store`.

Estados: `PENDING → IN_REVIEW → ACCEPTED_OFFLINE`, o rechazo explícito
`REJECTED`, con `REOPENED → IN_REVIEW` tras reabrir una decisión cerrada.
Una aceptación requiere razón humana, seis acknowledgements independientes,
políticas de aceptación y privacidad sin bloqueos, 13/13 escenarios sintéticos
pasados con cobertura completa y coincidencia de procedencia. El conjunto
de fixtures ejecutables es **sintético**, nunca aceptación de inventarios reales
ni test LIVE de OSV.dev.

La evidencia almacenada incluye snapshot de aceptación offline, snapshot de
privacidad, resumen de escenarios y digests SHA-256 de inventario, inspección,
aceptación, privacidad, escenario, políticas y bundle versionado. Los digests
no son firmas externas; la verificación independiente detecta cambios locales
en snapshots, identidad y decisiones. Se evalúa con el reloj original para
comparar la evidencia persistida y con la fecha actual para no reutilizar una
aprobación antigua si hoy aparece una caducidad o un bloqueo. Los propios
eventos del registro de liberación quedan excluidos del recuento de auditoría
del readiness de privacidad para impedir un ciclo autoinvalidante; las
operaciones del registro **sí** tienen su propia auditoría en la misma
transacción de la escritura del review.

El panel `AssetReleaseReviewWorkspace` muestra procedencia, exclusiones,
estados, revisiones, alertas y exportación JSON, y no permite marcar
acknowledgements automáticamente. Un estado `ACCEPTED_OFFLINE` **no**
certifica remediación, seguridad de endpoint, escaneos de todos los activos,
disponibilidad LIVE de proveedores, borrado de backups ni aprobación legal.
La política de privacidad/retención debe pasar por revisión humana efectiva
y el registro no sustituye las autorizaciones externas que correspondan.

### Aceptación aún exigida antes de fusionar

- Confirmar TypeScript, migraciones, PostgreSQL, tests, build y los cinco
  workflows del **mismo HEAD**.
- Ejecutar recorrido manual reproducible con inventarios representativos,
  inspección OSV previamente guardada, casos humanos, análisis offline,
  privacidad/retención y la decisión humana registrada; retener sus evidencias.
- Exigir revisión real de privacidad/retención, incluyendo procedimiento de
  backup y copias exportadas. La matriz sintética no suple esta revisión.
- Mantener el PR en Draft y sin fusionar hasta cerrar estos pasos.


## CC 11/11/2026: trazabilidad forense y revisión de retención (sin tenants externos)

### C1 — Dossier de auditoría de decisiones humanas

- Motor `assets-release-audit-dossier.ts`: reconstrucción read-only de todos los
  `AuditEvent` vinculados al `AssetReleaseReview` del tenant, sin promover
  estados desconocidos ni crear eventos para suplir lagunas. Contrasta
  secuencias CAS, estados, decisiones, actores, motivos, digests y cobertura.
- API administrativa `POST /api/organizations/[slug]/assets/release-audit-dossier`,
  limitada por tamaño y número de eventos, acceso ADMIN/OWNER y no-store.
- Consola `AssetReleaseAuditDossierWorkspace`: selección de revisión,
  timeline, incidencias, evidencias, correcciones propuestas y exportación JSON.
- El `digest` del dossier prueba consistencia local, no autoría o firma externa.
  Un log local consistente tampoco representa aceptación humana externa, proveedor
  LIVE, parche aplicado, aprobación de retención o eliminación de backup.

### C2 — Registro administrativo de excepciones de privacidad y retención

- Prisma `AssetRetentionReview` y migración
  `20261111124500_asset_retention_reviews`: unicidad por organización/import,
  estado CAS, fechas de revisión, snapshots JSONB de evidencia con bytes
  canónicos, digests, responsables y limitaciones. La relación se acota
  a la organización; se comprueba el inventario en la evaluación del servidor.
- Servicio `assets-retention-review-service.ts`: lee el informe real
  `inspectAssetPrivacyReadiness` del tenant sin proveedores ni escrituras,
  exige un inventario presente, correlaciona cada gate de revisión/bloqueo
  con excepciones documentadas y responsables/fechas futuras, y permite
  transiciones humanas `PENDING → IN_REVIEW → DOCUMENTED_WITH_EXCEPTIONS`
  o `REJECTED`, con reapertura explícita. Un documento con excepciones
  **no** convierte gates de privacidad en PASS.
- API `GET/POST/PATCH/PUT /api/organizations/[slug]/assets/retention-reviews`,
  donde PUT es previsualización read-only y los demás métodos gestionan
  registro, lista y CAS auditado, siempre ADMIN/OWNER y sin caché.
- Consola `AssetRetentionReviewWorkspace`: política, acknowledgements
  sin preseleccionar, excepciones por gate, responsable, razón, referencia
  externa, fechas y procedimiento de backups, historial de estado y exportación.
- Las acciones de auditoría `assetRetention.review.*` se mantienen
  fuera del recuento `assets.*` del motor original de privacidad, de modo
  que documentar el resultado no altera su propia entrada de evaluación;
  las decisiones quedan registradas transaccionalmente con actor y tenant.
- `DOCUMENTED_WITH_EXCEPTIONS` indica únicamente que un responsable
  describió excepciones, no que se hayan resuelto, autorizado por un DPO,
  eliminado copias ni cumplido un mandato legal. Requiere validación
  independiente y revisión operativa humana posterior.

### Condiciones de aceptación pendientes

Los motores y fixtures offline sirven para preparación y validación técnica.
El cierre real requiere ejecutar un recorrido manual con inventarios
representativos y datos controlados, verificar las personas responsables,
aceptar explícitamente políticas de privacidad/retención aplicables,
confirmar procedimientos de backup y copias exportadas y conservar la
evidencia de esa aceptación. Sin esos hitos, se mantiene el PR en Draft,
sin fusionar, y ninguna función se declara LIVE.


## CC 11/11/2026 — preparación de cierre offline reproducible y recorrido humano

### C1: expediente integral de cierre, sin efectos secundarios

`assets-offline-closeout-dossier.ts` reúne exclusivamente fuentes
persistidas del mismo tenant: inventario CSV, inspección OSV guardada,
correlación y casos auditados, evaluación offline, privacidad y retención,
registro de decisión humana, dossier forense de auditoría y los trece
escenarios sintéticos de regresión. Produce un gatebook explícito
con estados `PASS`, `BLOCK`, `REVIEW`, `EXCLUDED`, digests locales,
manifiesto de procedencia y plan de actuaciones.

La API `POST /api/organizations/[slug]/assets/offline-closeout-dossier`
exige ADMIN/OWNER, IDs exactos, bindings explícitos, políticas acotadas,
respuestas no-store y ningún acceso al proveedor. La consola
`AssetOfflineCloseoutDossierWorkspace` ofrece filtros, diferencias de
origen, exportación del expediente y checklist local claramente marcado
como **no verificado**. Los indicadores `offlineProductAccepted`,
`mergeAuthorized`, `liveProviderValidated`, `legalSignoffConfirmed`
y `backupErasureConfirmed` permanecen explícitamente `false`.

Un dossier con gates verdes **no** sustituye un recorrido real ni una
decisión humana. Las exclusiones LIVE permanecen explícitas.

### C2: ejecución presenciada del checklist offline

`AssetOfflineAcceptanceRun` contiene un registro auditado de una ejecución
de nueve tareas: validación CSV, alcance, OSV persistido, casos,
controles offline, privacidad, retención/backups, auditoría de liberación
y recorrido manual. Su migración es
`20261111130000_asset_offline_acceptance_runs`.

`assets-offline-acceptance-run-service.ts` aplica RBAC ADMIN/OWNER,
idempotencia, límites de tamaño, nueve pasos fijos, referencias concretas
de evidencia, motivos de operador, compare-and-swap y auditoría en la
misma transacción PostgreSQL. Los estados `DRAFT`, `IN_PROGRESS`,
`BLOCKED`, `EVIDENCE_CAPTURED` y `REOPENED` nunca equivalen a una
aprobación externa. `SUBMIT_FOR_INDEPENDENT_REVIEW` exige nueve pasos
documentados y controles actuales sin bloqueo, y aun así solo registra
que la evidencia está preparada para **revisión independiente**.

La API `GET/POST/PATCH/PUT /api/organizations/[slug]/assets/offline-acceptance-runs`
separa listado, creación, cambios CAS y lectura de auditoría/manifiesto;
todas las solicitudes permanecen vinculadas al tenant autenticado y
no usan un proveedor externo. La consola administrativa
`AssetOfflineAcceptanceRunWorkspace` permite registrar observaciones,
IDs de evidencia, responsables, bloqueos, reaperturas, reconocimientos
no preseleccionados y exportación del historial.

**No existe ninguna operación que marque la fase como fusionable,
autorice un borrado de backups, declare legalmente aprobada una política
o finja una firma humana.** Las referencias introducidas manualmente
son declaraciones sujetas a verificación independiente.

### Protocolo para aceptación final

1. Usar inventario controlado y representativo y recopilar su origen,
   cobertura, consentimiento operativo y versiones documentadas.
2. Importar el CSV y generar o seleccionar una inspección OSV *persistida*;
   preservar IDs exactos y snapshots para reproducir el resultado.
3. Recorrer acciones guiadas y casos humanos, comprobar fingerprints,
   estados, checklist, auditoría y cobertura incompleta/UNKNOWN.
4. Generar el dossier `offline-closeout-dossier` y registrar todos
   los blockers, gates de revisión y exclusiones LIVE.
5. Documentar responsable de privacidad/retención y procedimientos de
   backups, copias exportadas, períodos de restauración y excepciones.
6. Ejecutar en la aplicación el checklist de nueve pasos con operador
   identificado, explicación suficiente y referencia verificable de
   cada elemento observado; no registrar evidencia no obtenida.
7. Revisar y exportar el expediente y el manifiesto de auditoría, con
   controles de tenant, identidad, completitud y revisión CAS.
8. Obtener el visto bueno real de los responsables competentes fuera
   de cualquier fixture, registrar claramente limitaciones y rechazo
   si faltan aprobaciones; la automatización nunca lo suple.
9. Verificar los cinco workflows sobre el HEAD definitivo y fusionar
   solo después de la autorización de producto correspondiente.

Las políticas de retención, el signoff legal y el ciclo de copias de
seguridad no se consideran aprobados por un digest, un checklist
marcado o un resultado sintético. El PR permanece en Draft hasta
completar los pasos humanos pendientes.


## CC 11/11/2026 — conciliación forense y tablero de cierre operativo

### Bloque C1: conciliación de las dos cadenas de auditoría CAS

El nuevo motor `assets-acceptance-audit-reconciliation.ts` comprueba
de forma independiente y **solo lectura** la cronología completa del
registro de recorrido humano `AssetOfflineAcceptanceRun` y de cada
`AssetEvidenceReview` independiente. Construye dos secuencias de eventos
CAS vinculadas al tenant, rechazando silencios de auditoría, revisiones
duplicadas, ausentes, fuera de orden, referencias cambiadas, decisiones
sin actor, auto-revisión, estados incompatibles y claims externos
no corroborados.

La ruta `POST /api/organizations/[slug]/assets/acceptance-audit-reconciliation`
requiere ADMIN/OWNER, un ID exacto, límite de eventos de 1 a 1000 por
cadena y entrada JSON máxima de 8 KiB. Si el histórico supera el límite,
se rechaza en lugar de presentar datos truncados como aceptación. La
interfaz `AssetAcceptanceAuditReconciliationWorkspace` permite filtrar
incidencias, estados por revisor, ver líneas temporales CAS y exportar
informe, digests y playbook manual. Ningún evento se reescribe ni se
crea para suplir huecos.

La verificación de hashes y eventos locales prueba únicamente
consistencia interna dentro de los límites definidos; **no** autentica
identidad externa, no demuestra remedio, no valida un proveedor
LIVE, no concede cumplimiento legal ni autoriza fusión.

### Bloque C2: mapa de dependencias para el cierre de producto offline

`assets-phase4-operational-closeout.ts` evalúa catorce áreas:
inventario declarado, OSV guardado, casos humanos, matriz sintética,
privacidad, retención, backups/exportaciones, recorrido de operador,
verificación independiente, revisión de liberación, auditoría CAS,
aceptación humana de producto, estado CI del HEAD y exclusión LIVE.

Cada área presenta `PASS_LOCAL`, `BLOCKED`, `HUMAN_REVIEW` o
`EXCLUDED`, responsable funcional, referencia de evidencia,
precondiciones y siguiente actuación. Los estados locales `PASS_LOCAL`
no conceden autorizaciones legales ni prueban decisiones humanas.
El bloque calcula dependencias insatisfechas, mapa por responsables y
expediente JSON con huella SHA-256 e indicadores conservadores.

La ruta `POST /api/organizations/[slug]/assets/phase4-operational-closeout`
y el componente `AssetPhase4OperationalCloseoutWorkspace` ofrecen
acceso administrativo tenant-scoped, read-only y no-store.
CI y GitHub se consideran `HUMAN_REVIEW` dentro de esta herramienta
porque su servicio solo consulta PostgreSQL: **no consulta el estado
autoritativo del HEAD**. La verificación GitHub se efectúa separadamente
sobre el commit real.

Pruebas Vitest cubren validación de entrada, permisos, sabotajes de
dossier, revisión independiente, dependencias y ausencia de
aprobaciones ficticias. La integración PostgreSQL reutiliza un
inventario y una inspección persistida de prueba, contrasta auditoría
CAS, aislamiento entre organizaciones y ausencia de escrituras en
consultas forenses.

**Límite de esta entrega:** preparar material y diagnosticar lo
pendiente no ejecuta el recorrido presencial real ni reemplaza al
operador, al responsable de privacidad/retención, al propietario
de backups o a la autorización de fusión. Si falta aprobación, la
acción queda abierta; no se generan declaraciones positivas ficticias.

### Criterios finales

- Ejecutar manualmente un flujo representativo CSV → inspection →
  acciones → casos humanos → dossier → operator run → revisión separada.
- Comprobar personalmente la procedencia y contenido de referencias
  aportadas por operadores y registrar cualquier disputa o caducidad.
- Obtener responsables reales para privacidad, retención y backups,
  incluidos plazos, exportaciones y excepciones; conservar decisiones.
- Verificar las cadenas CAS de operación y revisor sin anomalías,
  y mantener cualquier caso parcial con resultado no aceptado.
- Confirmar CI, Security, Local stack E2E, LAB y Backup restore rehearsal
  sobre el **mismo HEAD** antes de valorar la fusión.
- Mantener el PR #211 en Draft sin fusionar mientras esos hitos humanos
  permanezcan sin resolver. Ningún tenant externo ni LIVE es necesario
  para el alcance offline definido.


## CC 12/11/2026 — cola de aceptación offline y expediente de traspaso humano

### C1: inventario paginado de pendientes de aceptación

`assets-phase4-acceptance-queue.ts` construye una cola administrativa
**read-only**, separada de cualquier scheduler. Analiza las ejecuciones
`AssetOfflineAcceptanceRun` dentro del tenant autenticado y una página
limitada (1–50), vinculando estados de los nueve pasos del operador,
revisiones independientes `AssetEvidenceReview`, antigüedad de
referencias, número de eventos de auditoría de la ejecución, revisión
de privacidad/retención y revisión de liberación offline.

La cola distingue **BLOCK**, **REVIEW** e **INFO**. Detecta
faltas de cobertura, autorevisiones, referencias modificadas o disputadas,
observaciones antiguas y discrepancias básicas entre número de eventos y
revisión CAS. Las discrepancias de contador son indicadores para
investigación: el motor forense `assets-acceptance-audit-reconciliation`
sigue siendo el responsable de reconstruir la cadena completa.

La API `POST /api/organizations/[slug]/assets/acceptance-queue`
requiere ADMIN/OWNER, JSON limitado a 8 KiB, límites por ejecución y
no-store. Su interfaz permite filtrar estados, criticidad, incidencias y
páginas; exporta una lista de acciones priorizadas para los responsables.
Los agregados son siempre **PAGE_ONLY**, no métricas globales de seguridad.

**No crea auditorías, no cambia findings/CyberScore, no envía correos,
no asigna aprobaciones y no interpreta una referencia como firma.**

### C2: expediente de preparación para la decisión humana

`assets-phase4-handoff-package.ts` compone los resultados del dossier
de cierre, el tablero operacional, la conciliación forense de los
CAS del operador/revisor y el resumen de referencias independientes
persistidas. Comprueba tenant, IDs de origen, digests y las advertencias
conservadoras. El paquete incluye:

- Doce referencias de fuente e informe con su procedencia,
  identificadores, digests locales y limitaciones explícitas.
- Nueve secciones de producto (procedencia, riesgo, operador,
  independencia, datos, backups, liberación, CI y decisión final).
- Nueve hitos de actuación con responsable, dependencia, entregable,
  evidencia local disponible y estados humanos **no verificables
  automáticamente**.
- Registro de cuestiones pendientes y plan de acciones por responsable;
  manifiesto exportable, SHA-256 local y controles de manipulación.

La API `POST /api/organizations/[slug]/assets/phase4-handoff`
requiere ADMIN/OWNER, tamaño máximo de 128 KiB y selección explícita
de inventario, inspección y recorrido humano, sin acceso a proveedores.
La consola `AssetPhase4HandoffWorkspace` permite revisar el expediente
y exportar un JSON; el usuario debe custodiarlo conforme a su
política de privacidad porque puede revelar referencias operativas.

La salida siempre declara `productAccepted:false`,
`githubMergeAuthorized:false`, `legalApproved:false`,
`backupDeletionVerified:false` y `providerRequests:0`.
Los tests validan parsers, límites, permisos, casos pendientes,
autorrevisión y manipulación; los ensayos PostgreSQL comprueban
aislamiento y que las evaluaciones no generan nuevas escrituras de
auditoría.

### Acciones pendientes para cerrar sin tenants externos

1. Ejecutar físicamente el recorrido offline CSV → OSV guardado →
   casos → aceptación y completar nueve pasos con referencias reales.
2. Corroborar las referencias por otro responsable autenticado y
   resolver falsos positivos, caducidades y discrepancias CAS.
3. Registrar y obtener aprobaciones reales de privacidad,
   conservación, copias exportadas y procedimiento de backups.
4. Documentar la aceptación de producto, sus exclusiones,
   los motivos y el responsable competente.
5. Verificar el HEAD exacto en GitHub con los cinco workflows SUCCESS
   antes de autorizar la fusión.

Los apartados LIVE, los tenants externos y la validación real de
proveedores siguen fuera de este cierre offline. El PR #211 debe
mantenerse en Draft hasta el acto de aceptación humana documentado.
