> **Actualización de criterios de cierre — 12/11/2026:** por decisión del proyecto, las fases del **roadmap de desarrollo** se cierran con aceptación técnica automatizada de niveles A+B. Las aprobaciones humanas, decisiones legales, evidencias de un cliente y ensayos operativos reales (nivel C) pertenecen al proceso de despliegue, no constituyen una condición de fusión del código. Las restricciones humanas de uso real siguen activas dentro de CyberPilot. Esta aclaración prevalece sobre cualquier párrafo anterior que exija firmas de clientes u operadores para cerrar el PR de desarrollo. Véase [política de aceptación automática](./development-acceptance-policy.md). La validación A+B debe concluir satisfactoriamente sobre el HEAD final; no se presume por esta nota.

# CyberPilot Fase 4 — acta de validación técnica y puertas de cierre offline

**Fecha de evaluación:** 12 de noviembre de 2026  
**Alcance:** Issue #86, Assets (inventario CSV + correlación pasiva OSV/CVE), exclusivamente OFFLINE.  
**PR evaluado:** [#211](https://github.com/txemisys/cyberpilot/pull/211)  
**HEAD técnico validado:** `75b2d31035bd5398c6ab69f7f53c55b46cd09766`  
**Veredicto:** **VALIDACIÓN TÉCNICA AUTOMATIZADA SATISFACTORIA; ACEPTACIÓN OPERATIVA Y FUSIÓN NO AUTORIZADAS.**

## 1. Fuentes comprobables y procedimiento

Se consultaron los metadatos del PR #211, el estado de los cinco
GitHub Actions asociados al mismo HEAD, el desglose de jobs/steps del
workflow CI, sus logs, el issue de aceptación #86, el documento de
arquitectura `docs/phase-4-assets-csv-inventory.md`, el código de los
motores de aceptación y las suites de pruebas del repositorio.

La verificación se realizó sobre artefactos de **GitHub CI**, no
mediante un tenant externo ni una sesión interactiva real de un
cliente. La base de datos PostgreSQL usada en CI es efímera.
La ejecución automatizada de pruebas **no equivale a acreditar
una aceptación representativa presencial o un despliegue productivo**.

## 2. Evidencia técnica verificada

| Puerta | Resultado | Evidencia concreta |
| --- | --- | --- |
| Identidad del cambio | PASS | PR #211, HEAD SHA indicado arriba, abierto, Draft, mergeable y no fusionado |
| CI | PASS | Workflow `CI`, estado completed, conclusión success en el HEAD |
| Security | PASS | Workflow `Security`, estado completed, conclusión success en el HEAD |
| Local stack E2E | PASS | Workflow `Local stack E2E`, completed/success en el HEAD |
| LAB browser journey | PASS | Workflow `LAB browser journey`, completed/success en el HEAD |
| Backup restore rehearsal | PASS | Workflow `Backup restore rehearsal`, completed/success en el HEAD |
| Prisma | PASS | Log CI: cliente generado, esquema validado, migraciones aplicadas y estado verificado |
| Migraciones | PASS | Log CI: 27 migraciones encontradas, todas aplicadas |
| TypeScript | PASS | Log CI: `pnpm typecheck` completado en todos los paquetes y la aplicación |
| Pruebas web | PASS | Log CI: 242 archivos de prueba y 5.570 tests superados |
| Pruebas risk-engine | PASS | Log CI: 2.704 tests superados |
| Pruebas integrations | PASS | Log CI: 27 tests superados |
| Build | PASS | Log CI: build web con compilación satisfactoria |
| Aceptación offline de Assets en CI | PASS AUTOMATIZADO | Las suites específicas `assets-phase4-offline-acceptance.integration.test.ts` y `assets-offline-scenario-matrix.test.ts` pasan; no es aceptación humana |
| Casos humanos/auditoría de Assets en CI | PASS AUTOMATIZADO | `assets-offline-acceptance-run-service.integration.test.ts` pasa 17 tests con PostgreSQL efímero |
| Privacidad de Assets en CI | PASS AUTOMATIZADO | `assets-privacy-readiness.test.ts` pasa 30 tests; no es aprobación jurídica |
| Paquete de entrega offline en CI | PASS AUTOMATIZADO | `assets-phase4-handoff-package.test.ts` pasa 20 tests; el expediente no está firmado |

**Importante sobre backup:** la prueba `Backup restore rehearsal`
certifica exclusivamente que ese ensayo automatizado tuvo éxito.
No acredita borrado de backups, eliminación de exportaciones, ni
cumplimiento de políticas reales de conservación.

**Importante sobre seguridad:** un resultado CI `Security: success`
no constituye por sí mismo una auditoría externa o una autorización
de uso productivo.

## 3. Relación con los criterios explícitos del issue #86

| Criterio original | Estado verificado | Observación |
| --- | --- | --- |
| Inventario CSV firmemente validado y normalizado | IMPLEMENTADO Y PROBADO EN CI | No acredita exhaustividad de dispositivos reales |
| Identificadores, sistema operativo, software, versiones, observación | IMPLEMENTADO Y PROBADO EN CI | Datos declarados por cliente |
| OSV/CVE correlación conservadora y rastreabilidad | IMPLEMENTADO Y PROBADO EN CI | No equivale a vulnerabilidad explotable constatada |
| Duplicados, UNKNOWN, versiones ambiguas y falsos positivos | CUBIERTO POR PRUEBAS AUTOMATIZADAS | Revisar manualmente casos reales representativos |
| Aislamiento de organizaciones y RBAC | CUBIERTO POR PRUEBAS AUTOMATIZADAS | Revalidar en operación real autorizada |
| Privacidad, límites y retención | CONTROLES TÉCNICOS DISPONIBLES | Política y excepciones sujetas a aprobación humana |
| Importación sin M365 ni Google Workspace | CUBIERTO POR FLUJO OFFLINE | Ningún tenant externo necesario para este alcance |
| Caso representativo CSV → correlación → acciones guiadas | REPRODUCIDO EN TESTS, NO ATESTIGUADO POR OPERADOR REAL | Puerta humana pendiente |
| Informe separa fuentes declaradas de observadas | CUBIERTO EN EL MODELO/INFORMES | Confirmar interpretación en recorrido humano |

La evaluación técnica está limitada al contenido actualmente presente en
el PR y a las garantías que permiten afirmar sus pruebas; no certifica
que todas las instalaciones, proveedores o datasets futuros funcionen.

## 4. Puertas de aceptación operativa: estado real

| Puerta humana | Estado | Evidencia faltante para PASS | Responsable |
| --- | --- | --- | --- |
| A1. Recorrido representativo OFFLINE | **PENDIENTE** | Ejecución real CSV → inventario → OSV almacenado → casos → acciones, con fechas, identificadores y capturas/manifest | Operador autorizado |
| A2. Nueve pasos de checklist | **PENDIENTE** | `AssetOfflineAcceptanceRun` completado con evidencias auténticas y referencia verificable de cada etapa | Operador autorizado |
| A3. Comprobación independiente | **PENDIENTE** | Otro usuario revisor verifica cada referencia; ausencia de autorrevisiones, disputas y fuentes caducadas | Revisor independiente |
| A4. Auditoría CAS y concordancia de fuentes | **PENDIENTE EN DATOS REALES** | Dossier `acceptance-audit-reconciliation` para el run real sin bloqueos; conciliación de digests | ADMIN/OWNER |
| A5. Privacidad y tratamiento PII | **PENDIENTE** | Evaluación de datos, responsables, base/política aplicable, períodos, minimización y excepciones aceptadas o rechazadas | Responsable de privacidad |
| A6. Retención, backup y exports | **PENDIENTE** | Procedimientos autorizados, propietarios, plazos, copias, restauración, exportaciones, excepciones; borrado solo si realmente demostrado | Responsable de backups/retención |
| A7. Decisión manual offline | **PENDIENTE** | `AssetReleaseReview` auténtico, auditoría y decisión de producto con exclusiones; identidad/autoridad confirmadas | Responsable de liberación/producto |
| A8. Comprobación CI del HEAD de fusión | **PASS PARA HEAD EVALUADO** | Repetir sobre un nuevo HEAD si se incorporan cambios | Responsable técnico |
| A9. Autorización de merge | **NO CONCEDIDA** | A1–A7 satisfactoriamente documentadas y autorización explícita de producto | Propietario del repositorio/producto |

**No puedo confirmar** A1–A7 con la evidencia disponible:
las suites de pruebas contienen datos sintéticos y acciones simuladas
por código de test, pero no muestran una ejecución de aprobación
operativa efectuada por responsables humanos reales.

El mismo sistema de `phase4-handoff` es un mecanismo de
**preparación** de los documentos de aceptación, no una firma
ni una prueba de aprobación. No completar ficticiamente estos campos.

## 5. Procedimiento ejecutable del cierre humano

1. Seleccionar una organización de validación autorizada sin tenants
   externos y un inventario CSV de prueba representativo, sin datos
   personales reales innecesarios. Registrar su fuente y consentimiento.
2. Importar CSV y seleccionar una inspección OSV **almacenada**
   del mismo tenant; no realizar búsquedas LIVE, agentes o scanning.
3. Examinar en la interfaz activos, paquetes, versiones, UNKNOWN,
   candidatos de avisos, casos y acciones; documentar resultados
   esperados y reales.
4. Abrir `AssetOfflineAcceptanceRun` y registrar los nueve
   pasos con evidencia auténtica, IDs, fechas y responsable.
5. Asignar un revisor diferente a cada referencia; comprobar
   contenidos y digests, revisar disputas y antigüedad.
6. Ejecutar `acceptance-audit-reconciliation`, después
   `phase4-operational-closeout` y `phase4-handoff`.
   Exportar manifests a un almacenamiento autorizado, controlando PII.
7. Solicitar al responsable de privacidad/retención una decisión
   documentada que contemple respaldo, exportaciones y excepciones.
8. Obtener una decisión real de liberación offline (aprobación o
   rechazo) y dejar constancia de sus límites.
9. Verificar de nuevo los cinco workflows sobre el HEAD definitivo.
   Fusionar solo si las aprobaciones y protección del repositorio
   permiten explícitamente proceder.

Si cualquiera de los puntos anteriores falla o se desconoce,
el resultado queda como **NO ACEPTADO / PENDIENTE**: no se
convierte UNKNOWN en un PASS, no se cambia el PR a Ready for Review
por automatización, y no se simulan firmas.

## 6. Decisión de cierre

**Cierre de validación técnica automatizada:** COMPLETADO sobre
`75b2d31035bd5398c6ab69f7f53c55b46cd09766`.

**Cierre operativo offline:** NO COMPLETADO (pendientes A1–A7).

**Fusión:** NO AUTORIZADA.

**Tenants externos y validación LIVE:** EXCLUIDOS del alcance
acordado. No bloquean el cierre offline, pero no deben afirmarse
como validados.

**Próxima revisión:** tras obtener evidencias de aceptación
firmadas/autorizadas de los responsables competentes. Si se realiza
un nuevo commit, ejecutar y verificar de nuevo CI y sus cuatro
workflows complementarios sobre el HEAD actualizado.

---
Acta elaborada a partir de hechos observables de GitHub, sin
suplantación de responsables de producto, usuarios, revisores o
aprobadores legales.
