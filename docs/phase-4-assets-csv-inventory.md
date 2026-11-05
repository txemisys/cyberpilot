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
