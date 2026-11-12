# CyberPilot — Fase 1 P0: núcleo multifuente v2

**Issue:** [#83](https://github.com/txemisys/cyberpilot/issues/83)  
**PR:** [#214](https://github.com/txemisys/cyberpilot/pull/214)  
**Modelo nuevo:** `cyberpilot.multisource.v2`, revisión 1, opt-in.  
**Modelo existente:** histórico v1 y tabla `SecurityScore`, **sin cambios**.

## Alcance A+B de desarrollo

Esta entrega construye un motor multifuente y un modelo de scoring
versionado que no depende de Microsoft 365. Mantiene los estados
`OBSERVED`, `DECLARED`, `UNKNOWN` y `ERROR`, el alcance por control,
la fuente, la fecha, la confianza, el origen técnico o declarado y la
autenticidad de cada ámbito. Ninguna fila incompleta puede convertirse
en una constatación de seguridad.

### Contratos y cobertura

- `multisource-v2-contract.ts`: contratos tipados `V2Evidence`,
  `V2ControlSpec`, `V2Finding`, `V2Scope`, `V2Manifest` y
  validaciones estrictas de tenant/procedencia, catálogo de 19 controles,
  ámbito y edad de evidencia.
- `multisource-v2-coverage.ts`: evaluación por control obligatorio,
  cobertura ponderada por dominio, caducidad, paginación incompleta,
  autenticidad de ámbitos, deduplicación y conflictos entre fuentes.
- La cobertura completa de un control no implica cobertura completa
  de todo el dominio o de la organización. Las declaraciones y fixtures
  no se promocionan a evidencia técnica verificada.

### CyberScore v2 y comparabilidad

- `multisource-v2-score.ts`: evaluación v2 separada, cálculo por
  severidad/confianza, límite de riesgo por dominio, deduplicación por
  regla/ámbito/sujeto, catálogo de contribuciones y comparador temporal.
- El score numérico solo se emite cuando hay cobertura verificada
  suficiente (mínimo 60 %, al menos 5 controles y una fuente LIVE
  debidamente autenticada y verificada), sin conflictos.
- Si no hay datos suficientes, `score: null` es un resultado
  funcional, no un error ni una estimación inventada. Las prioridades
  y el informe siguen siendo útiles con incertidumbre explícita.
- `multisource-v2-history.ts`: snapshots versionados, SHA-256
  determinista, encadenamiento de revisiones, comparación temporal
  entre snapshots v2 y advertencia de no comparabilidad numérica v1/v2.
- El modelo histórico v1 sigue accesible y **no se recalcula,
  migra ni reescribe** mediante estos flujos.

### Fuentes y experiencia sin Microsoft 365

- `multisource-v2-adapters.ts`: entrada neutral de M365, Google,
  LAB, Exposure, Baseline y Assets; validación de pertenencia,
  detalles minimizados y reglas para no inferir permisos LIVE.
- `multisource-v2-report.ts`: informe ejecutivo de 14 secciones,
  cobertura, control pendiente, riesgos, prioridades,
  procedencia, exportación JSON/CSV/Markdown y comparación conservadora.
- `/organizations/[slug]/multisource-v2`: pantalla opt-in, con
  demostración sintética sin M365, consulta del historial,
  filtros por control, exportación e informe.
- `/api/organizations/[slug]/multisource-v2`: operaciones autenticadas
  PREVIEW, STORE, LIST, READ, EXPORT y COMPARE.
- `MultiSourceV2Assessment` (Prisma y migración
  `20261112150000_multisource_cyberscore_v2`): almacenamiento propio
  con score nullable, digest de fuente/cobertura/score/informe,
  filtros tenant y auditoría transaccional. No modifica
  `SecurityScore`, sus migraciones ni el modelo original.

## Garantías y límites

1. Todas las operaciones de servidor requieren membresía actual.
   Almacenar un snapshot requiere OWNER o ADMIN.
2. El primer recorrido de producto crea **solamente una evaluación
   sintética y explícitamente no verificable**. La API no acepta
   directamente estados ficticios LIVE del navegador ni accede
   a credenciales externas.
3. Los adaptadores reales de fuentes quedan preparados como interfaces,
   pero no se presenta una conexión LIVE no autenticada como evidencia.
4. Las recomendaciones nunca ejecutan cambios sobre cuentas.
5. No se emiten certificaciones CIS, acreditaciones o consentimiento
   legal de cliente a partir de tests CI.
6. La disponibilidad futura de un tenant autorizado es un gate
   operativo independiente y no bloquea la aceptación A+B offline.
7. Los digests SHA-256 prueban consistencia local, no una firma externa.

## Aceptación automatizada A+B

- Pruebas de organización sin M365 con Exposure + Baseline + Assets,
  incluidas verificaciones de hallazgos, score `null` y cobertura
  incompleta explícita.
- Pruebas de tenant cruzado, errores, permisos parciales,
  datos desactualizados, estados declarados, conflictos y
  deduplicación conservadora.
- Pruebas de SHA-256, cadenas de historial y separación de modelo.
- Pruebas de integración PostgreSQL para acceso, persistencia
  sin escrituras v1, auditoría, exportación y aislamiento.
- Workflow independiente `Multi-source CyberScore v2 development
  closeout` en HEAD del PR, además de CI, Security,
  LAB, Local stack y Backup rehearsal cuando se ejecuten.
- **No fusionar sin checks verdes sobre el último HEAD.**

La aceptación de desarrollo puede completarse automáticamente;
no pretende constituir una aprobación comercial o de seguridad
de un entorno LIVE.
