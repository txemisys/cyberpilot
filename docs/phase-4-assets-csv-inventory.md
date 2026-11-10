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
