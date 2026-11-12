# CyberPilot — Exposure + Baseline, desarrollo offline ampliado

**Fecha de corte:** 12/11/2026  
**Repositorio:** [CyberPilot](https://github.com/txemisys/cyberpilot)  
**Issues de roadmap:** [#84 Exposure](https://github.com/txemisys/cyberpilot/issues/84), [#85 Baseline](https://github.com/txemisys/cyberpilot/issues/85)  
**PR:** [#216](https://github.com/txemisys/cyberpilot/pull/216)

## Alcance realmente implementado

Se amplía la Fase 2 existente sin tocar el CyberScore histórico ni
convertir una prueba con fixtures en un despliegue real de cliente.

### C1 — Exposure offline pasivo

- `exposure-offline-v2.ts`: contrato de evaluación por organización y
  dominio, atribución explícita de autorización y procedencia,
  clasificación de DNS/SPF, DMARC, DKIM, TLS, cabeceras HTTP y
  redirecciones.
- Recibe datos recopilados previamente y **no realiza DNS,
  HTTP ni TLS de red**. Las observaciones incompletas, errores,
  NXDOMAIN, timeout, permisos y falta de selectores se mantienen
  como UNKNOWN/ERROR. El inventario parcial no se convierte en
  valoración Healthy.
- Comprobaciones conservadoras de dominios y direcciones privadas;
  se rechazan objetivos internos y respuestas HTTP cuyos destinos
  finales no pertenezcan a las direcciones resueltas proporcionadas.
  La coincidencia de nombre TLS se valida como señal adicional.
- `exposure-offline-report-v2.ts`: informe de 10 secciones,
  propuesta de prioridades, cobertura por control, exportación
  JSON/CSV/Markdown, verificación SHA-256 y comparación temporal.
- Las reglas y resultados son **interpretaciones locales** de
  observaciones aportadas; no constituyen prueba de titularidad ni
  seguridad de un proveedor LIVE.

### C2 — Baseline declarativo

- Se reutilizan las preguntas preexistentes
  `BASELINE_IG1_QUESTIONS` versión 1, preservando IDs, dominios,
  respuestas y metodología del repositorio.
- `baseline-offline-v2.ts`: validación por tenant, respuesta
  YES/PARTIAL/NO/UNKNOWN/NOT_APPLICABLE/UNANSWERED,
  evaluación de cobertura declarativa, indicación de evidencia
  faltante y acciones prioritarias con guía y plazos **orientativos**.
- La respuesta positiva y una referencia documental no constituyen
  comprobación técnica. El modelo devuelve `score: null` y
  `technicalCoveragePercent: 0` en todos estos expedientes.
- Las notas libres y referencias potencialmente sensibles se
  descartan del informe, conservando únicamente identificadores
  opacos aceptables; las recomendaciones no ejecutan cambios.
- `baseline-offline-report-v2.ts`: informe ejecutivo,
  plan de acciones, tendencias y exportación segura
  JSON/CSV/Markdown, sin atribuir certificación CIS.

### C3 — Integración multifuente y recorrido web

- `exposure-baseline-v2-bridge.ts`: proyección de Exposure y
  Baseline a las interfaces del motor `cyberpilot.multisource.v2`,
  sin elevar fixtures o autodeclaraciones a
  `TECHNICALLY_VERIFIED`.
- `exposure-baseline-v2-portfolio.ts`: expediente de una
  organización sin Microsoft 365, con fuentes, riesgo
  candidato, evidencia, cobertura, prioridades y comparación.
- `/organizations/[slug]/baseline`: pantalla de cuestionario
  por áreas, filtro, progreso local en memoria, plan visible e
  informes descargables.
- `/api/organizations/[slug]/phase2-offline`: evaluación bajo
  sesión organizativa existente, restricciones de origen, tamaño,
  pertenencia e importación exclusivamente offline.
- La pantalla y el endpoint permiten **vista previa y exportación**.
  En este PR no se ha implementado todavía el **guardado persistente
  de borradores y respuestas Baseline**, ni una programación de
  escaneos de dominios LIVE; por tanto no se marca como cerrado
  todo el alcance de #84 o #85.
- No se han añadido migraciones que afecten a `SecurityScore` v1.

## Criterios A+B comprobables

La aceptación automatizada de este PR exige:
- TypeScript y tests del motor de riesgo, sin cambios de versión
  del cuestionario original.
- Fixtures sobre evidencias ya aportadas: DNS/SPF/DMARC,
  selectores DKIM desconocidos, TLS con nombre no coincidente,
  cabeceras y dirección IP final no autorizada.
- Pruebas de declaraciones, detalles redactados,
  procedencia y comparaciones temporales, sin falsa certificación.
- Integración sin Microsoft 365 usando al menos una fuente
  Exposure más el cuestionario, sin calcular puntuación
  no verificada y con aislamiento por organización.
- Workflow `Phase 2 Exposure Baseline offline closeout`
  y los checks generales del mismo HEAD antes de fusionar.

## Pendiente en los issues originales

**#84 — Exposure:** verificación de titularidad real, cuotas y
autorización persistida para un escáner pasivo LIVE controlado,
comportamiento DNS/TLS/HTTP real sometido a límites, pruebas
anti-SSRF y no intrusivas, y trazabilidad persistida.

**#85 — Baseline:** almacenamiento de borradores, revisiones,
historial y auditoría persistida por usuario/organización,
integración integral del ciclo de remediación y aceptación
operativa completa. Ningún requisito se considera completado
por existir solamente un informe offline.

Las tareas que requieran consentimiento legal o un cliente LIVE
siguen separadas del cierre A+B de desarrollo. Nunca se generan
firmas humanas ficticias.
