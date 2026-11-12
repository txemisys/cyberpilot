# CyberPilot — política de aceptación automática del desarrollo (v1)

**Vigente desde:** 12 de noviembre de 2026.  
**Primer ámbito:** Fase 4, issue [#86](https://github.com/txemisys/cyberpilot/issues/86), PR [#211](https://github.com/txemisys/cyberpilot/pull/211).  
**Propósito:** permitir cierres reproducibles de fases de desarrollo sin
convertir firmas, pruebas presenciales o credenciales de clientes en
dependencias artificiales del roadmap.

## 1. Distinción fundamental

Se adoptan **tres niveles de evidencia distintos**:

| Nivel | Concepto | Puerta de cierre de desarrollo | Resultado |
| --- | --- | --- | --- |
| A | Implementación y regresión funcional | Obligatorio | Funcionalidad y pruebas verificables |
| B | Validación técnica automatizada | Obligatorio | CI, seguridad, integración, E2E, backup rehearsal y build |
| C | Aceptación operativa empresarial | **Fuera del cierre de desarrollo** | Procedimientos y decisiones de una organización real, en el despliegue correspondiente |

Cerrar A+B **no equivale a aprobar C**. No se deben confundir:
- CSV declarado con descubrimiento activo real;
- CVE posible con explotación verificada;
- correlación OSV almacenada con comprobación LIVE actual;
- test de restauración con borrado de todos los backups;
- hash SHA-256 local con una firma de tercero;
- una cuenta de pruebas con una persona autorizada;
- código probado con cumplimiento legal o certificación;
- un PR fusionado con un despliegue empresarial aprobado.

La aplicación conserva sus restricciones operativas, RBAC,
aislamiento multitenant, privacidad, UNKNOWN, ERROR, registros CAS y
requerimientos de decisiones humanas cuando son propios del
**uso por clientes**. Esta política no autoriza eliminar dichos
controles del producto.

## 2. Aceptación del desarrollo en Fase 4

**Criterio:** la Fase 4 offline está técnicamente lista para fusionarse
cuando el HEAD exacto del PR cumpla todos los siguientes puntos:

1. El issue #86 tiene cobertura funcional real en código y tests
   de CSV, normalización, fuente declarada, OSV histórico,
   correlación conservadora, falsos positivos y desconocidos.
2. Se conserva el tratamiento seguro de inventarios parciales,
   versiones ambiguas, candidatos sin caso y evidencia sin auditoría.
3. Se preservan RBAC, aislamiento de organizaciones, límites de
   payload, minimización de PII y ausencia de claims no verificados.
4. Los **13 escenarios** de referencia offline están presentes y
   pasan al ejecutarse en la suite; ejecución parcial no basta.
5. Las pruebas PostgreSQL de recorridos offline, revisión de casos,
   estados del operador y contradicciones CAS se ejecutan en CI.
6. Migraciones Prisma, tipado TypeScript y tests completos pasan.
7. El **build de producción** pasa después del test y del gate,
   nunca se presume desde un resultado anterior.
8. Exactamente cinco workflows obligatorios están `completed`
   con conclusión `success` en el mismo SHA del PR:
   **CI, Security, Local stack E2E, LAB browser journey y
   Backup restore rehearsal**.
9. Una verificación independiente obtiene el estado de GitHub,
   comprueba que el HEAD sigue siendo el mismo, valida cada paso
   relevante del CI y emite un manifiesto de cierre con digest.
10. Ninguna advertencia, exclusión o evidencia UNKNOWN se eleva
    automáticamente a certeza, legalidad, firma o aprobación LIVE.

**La aceptación A+B no necesita que un humano ejecute nueve pasos,
revise referencias de clientes, firme privacidad o apruebe procedimientos
reales de backup.** Esas responsabilidades pertenecen al nivel C.
Un desarrollador puede mejorar los tests usando fixtures reproducibles
y datos sintéticos controlados sin aparentar que son personas reales.

## 3. Mecanismos implementados

### Gate integrado dentro de CI

`scripts/phase4-development-acceptance.mjs` verifica el inventario
de 16 contratos de fuente/test, el catálogo de 13 escenarios, la
presencia de garantías y la identidad SHA del checkout. Rechaza
bypass explícitos, files ausentes o cambios inesperados de criterios.

Tras `pnpm test`, `.github/workflows/ci.yml` ejecuta pruebas
`node:test` del gate y produce el manifiesto:

`.artifacts/phase4-development-acceptance.json`

Lo sube como artefacto de GitHub Actions por 30 días. Este manifiesto
contiene **evidencia de fuente e informe técnico parcial**:
en su momento el build posterior y cuatro workflows externos pueden
seguir pendientes. Jamás se debe usar por sí solo para fusionar.

### Verificador independiente de cinco workflows

`scripts/phase4-workflow-closeout.mjs` consulta la API de GitHub
**solo con GET** y permisos mínimos de lectura. Contrasta:
- identidad, estado abierto y SHA actual del PR;
- los cinco workflows, evento `pull_request`, mismo HEAD,
  `completed/success`, con rechazo de runs antiguos que
  fueron sustituidos por nuevas ejecuciones;
- pasos obligatorios: migraciones, estado de migraciones,
  TypeScript, tests, gate de desarrollo y build, todos exitosos
  y en orden;
- ausencia de versiones ambiguas del resultado.

El workflow `.github/workflows/phase4-development-closeout.yml`
espera acotadamente a que concluyan los demás checks y publica
un documento de **cierre técnico A+B** como artefacto:
`.artifacts/phase4-workflow-closeout.json`

Si falta cualquier resultado, el workflow falla; no inventa estado.
Si GitHub no permite acceder a resultados, se debe mostrar
**NO VERIFICABLE** en vez de afirmar que pasó. El verificador no
cambia el estado del PR ni fusiona.

### Pruebas negativas

Los ficheros `scripts/phase4-development-acceptance.test.mjs` y
`scripts/phase4-workflow-closeout.test.mjs` contienen regresiones
para SHA ajeno, run pendiente/fallido, CI incompleto, orden incorrecto,
path traversal, saltos de permisos, manifiestos alterados,
firmas inexistentes y clasificación inadecuada de fixtures.

**Condición técnica permanente:** los tests no pueden acreditarse
como aprobaciones humanas de privacidad, continuidad empresarial,
cumplimiento o firma externa.

## 4. Criterios de fusión

El PR puede salir de Draft **después de A+B**, si los controles
del repositorio lo permiten; la decisión final de fusión sigue
sujeta a permisos y políticas de GitHub.

No modificar protecciones de `main` para forzar la fusión.
Ante un error de permisos, una revisión obligatoria o un conflicto,
conservar el PR y registrar el bloqueo real.

Después del merge, el issue de desarrollo puede cerrarse cuando
las pruebas que lo acreditan estén incorporadas a `main` y
no queden criterios funcionales offline sin implementar.

El merge en `main` **no autoriza un despliegue LIVE**,
no activa integraciones externas y no modifica criterios
de aceptación de clientes.

## 5. Obligaciones del nivel C — uso real

Cuando CyberPilot se utilice en una organización real, sus usuarios
serán responsables de las decisiones y evidencias que la aplicación
requiera para su contexto:

- aceptación del alcance y cobertura de inventario;
- comprobación de referencias y aprobación de casos;
- privacidad, tratamientos, conservación y exportaciones;
- continuidad, backups, recuperaciones y eliminación de copias;
- credenciales, permisos y consentimiento para integraciones LIVE;
- decisiones de producto, remediación y liberación reales.

Estas actividades se ejecutan y registran en los flujos del producto
cuando corresponda. **No son prerequisitos de cerrar las fases del
repositorio en un proceso de vibe coding.**

## 6. Aplicación a otras fases

La misma distinción A/B frente a C se incorpora al roadmap futuro,
adaptando el catálogo específico de controles a las funcionalidades
reales de cada fase.

No se aceptan porcentajes arbitrarios, conteo de líneas o
número de workflows como sustituto de funcionalidad y tests
reales. Tampoco se omiten dependencias externas cuando sí son
intrínsecas al alcance de un módulo; deberán tener un contrato
de integración verificable, fixtures y pruebas, y declarar
explícitamente la ausencia de verificación LIVE si faltan credenciales.

## 7. Registro de decisión

**Decisión:** utilizar aceptación automática reproducible A+B
como criterio de cierre de fases de desarrollo.

**Fuera del cierre:** firmas humanas de operadores, revisores,
responsables legales o del cliente; esas firmas no se simulan.

**Garantía:** las defensas del producto permanecen activas,
las pruebas mantienen escenarios negativos y los manifiestos
no se presentan como certificación.

**Traza:** PR #211, issue #86, workflows del commit exacto y
artefactos de evidencia. Cualquier nueva modificación requiere
revalidar el HEAD.
