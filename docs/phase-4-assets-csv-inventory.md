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
