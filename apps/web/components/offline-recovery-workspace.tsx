"use client";
import{useMemo,useState}from "react";
import type{OfflineRecoveryRehearsal,RecoveryRehearsalPolicy,
 RecoveryGate,RecoveryRehearsalDiff}from
 "../lib/offline-recovery-rehearsal-domain";
import type{OfflineCaptureKind}from "../lib/offline-report-capture-domain";
type RecoveryRow={
 id:string;organizationId:string;createdAt:string;createdById:string;
 status:string;digest:string;selectedCaptures:number;blockedGates:number;
 unverifiableGates:number;report:OfflineRecoveryRehearsal;
};
type Inventory={organizationId:string;truncated:boolean;
 entries:RecoveryRow[];summary:{total:number;passed:number;
 blocked:number;incomplete:number;issues:number};
 databaseRestores:0;providerCalls:0;externalCertification:false};
type Matrix={organizationId:string;matrix:Array<{
 kind:OfflineCaptureKind;selectedCaptureId:string|null;
 availableCaptures:number;latestSourceComplete:boolean;
 localDigestVerified:boolean;
 }>;requiredKindsMissing:string[];
 preview:OfflineRecoveryRehearsal|null;blocking:boolean;
 noSqlRestoreExecuted:true;noLiveProviderCalls:true};
type Envelope={data:unknown;providerCalls:0;databaseRestores:0;
 customerCertified:false;scoreV1Writes:0};
type Tab="RUNS"|"SELECT"|"MATRIX"|"GATES"|"AUDIT"|"COMPARISON";
const card:React.CSSProperties={border:"1px solid #94a3b866",
 borderRadius:12,padding:18,marginBottom:16};
const button:React.CSSProperties={
 border:"1px solid #64748b88",borderRadius:8,
 background:"transparent",color:"inherit",padding:"8px 12px",
 cursor:"pointer"};
const flex:React.CSSProperties={
 display:"flex",flexWrap:"wrap",alignItems:"center",gap:12};
function Stat({name,value}:{name:string;value:string|number}){
 return <div style={{...card,flex:"1 1 130px",minWidth:130}}>
 <small>{name}</small><p style={{fontSize:24,fontWeight:750}}>
 {value}</p></div>;
}
function Gate({gate}:{gate:RecoveryGate}){
 const color=gate.status==="BLOCK"?"#b91c1c":
 gate.status==="PASS"?"#0f766e":"#a16207";
 return <article style={card}>
 <h4>{gate.id} · <span style={{color}}>{gate.status}</span></h4>
 <p>{gate.reason}</p>
 <p>Capturas: {gate.affectedCaptures.length?
 gate.affectedCaptures.join(", "):"Ninguna"}</p>
 <p>Intervención humana: {
 gate.requiresHumanIntervention?"Necesaria":"No necesaria"}</p>
 <p>Atestación externa: NO.</p>
 </article>;
}
function download(artifact:{filename:string;mime:string;content:string}){
 if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
 throw Error("Nombre inválido");
 const url=URL.createObjectURL(new Blob([artifact.content],
 {type:artifact.mime}));
 const anchor=document.createElement("a");
 anchor.href=url;anchor.download=artifact.filename;
 document.body.append(anchor);anchor.click();anchor.remove();
 URL.revokeObjectURL(url);
}
export function OfflineRecoveryWorkspace({slug,organizationId,canWrite}:{
 slug:string;organizationId:string;canWrite:boolean;
}){
 const [inventory,setInventory]=useState<Inventory|null>(null);
 const [matrix,setMatrix]=useState<Matrix|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState("");
 const [notice,setNotice]=useState(""),[tab,setTab]=useState<Tab>("RUNS");
 const [selected,setSelected]=useState("");
 const [chosen,setChosen]=useState<string[]>([]);
 const [strict,setStrict]=useState(true);
 const [requireLinks,setRequireLinks]=useState(true);
 const [maxAge,setMaxAge]=useState(30);
 const [requireUnique,setRequireUnique]=useState(true);
 const [compareFirst,setCompareFirst]=useState("");
 const [compareLast,setCompareLast]=useState("");
 const [comparison,setComparison]=useState<RecoveryRehearsalDiff|null>(null);
 const [showWarnings,setShowWarnings]=useState(true);
 const [statusFilter,setStatusFilter]=useState("ALL");
 const [limit,setLimit]=useState(25);
 const endpoint="/api/organizations/"+encodeURIComponent(slug)+
 "/offline-recovery";
 const execute=async(task:()=>Promise<void>)=>{
 if(busy)return;setBusy(true);setError("");setNotice("");
 try{await task();}
 catch(cause){setError(cause instanceof Error?cause.message:
 "Ensayo rechazado");}
 finally{setBusy(false);}
 };
 const get=async(suffix="")=>{
 const res=await fetch(endpoint+suffix,{cache:"no-store"});
 const payload=await res.json() as Partial<Envelope>;
 if(!res.ok||payload.providerCalls!==0||
 payload.databaseRestores!==0||payload.customerCertified!==false||
 payload.scoreV1Writes!==0)
 throw Error("Respuesta de recuperación no verificable");
 return payload.data;
 };
 const refresh=async()=>{
 const list=await get() as Inventory;
 if(list.organizationId!==organizationId)
 throw Error("Resultados de otra organización");
 setInventory(list);
 };
 const load=()=>execute(async()=>{
 await refresh();setTab("RUNS");
 setNotice("Historial de ensayos de integridad verificado.");
 });
 const loadMatrix=()=>execute(async()=>{
 const data=await get("?mode=MATRIX") as Matrix;
 if(data.organizationId!==organizationId||
 data.noSqlRestoreExecuted!==true||
 data.noLiveProviderCalls!==true)
 throw Error("Matriz insegura o de otro tenant");
 setMatrix(data);
 setChosen(data.matrix.map(x=>x.selectedCaptureId)
 .filter((x):x is string=>x!==null));
 setTab("MATRIX");setNotice("Origen y disponibilidad reconciliados.");
 });
 const run=()=>execute(async()=>{
 if(!canWrite)throw Error("Rol sin permiso para ensayar");
 if(chosen.length===0)throw Error("Selecciona capturas primero");
 const policy:RecoveryRehearsalPolicy={
 requiredKinds:["INTEGRATED_RISKS","EVIDENCE_DECISIONS",
 "EXECUTIVE","LONGITUDINAL"],
 maxAgeDays:maxAge,requireCompleteSources:strict,
 requireCrossReportBindings:requireLinks,
 refuseDuplicateKinds:requireUnique,
 failOnSourceClassChanges:true,
 };
 const res=await fetch(endpoint,{method:"POST",cache:"no-store",
 headers:{"Content-Type":"application/json"},
 body:JSON.stringify({captureIds:chosen,policy})});
 const payload=await res.json() as Record<string,unknown>;
 if(!res.ok)throw Error(typeof payload.code==="string"?
 payload.code:"No se pudo registrar el ensayo");
 if(payload.providerCalls!==0||payload.databaseRestores!==0||
 payload.customerCertified!==false||payload.scoreV1Writes!==0)
 throw Error("Resultado no permitido");
 await refresh();setTab("RUNS");setChosen([]);
 setNotice("Ensayo de artefactos registrado sin restauración SQL.");
 });
 const compare=()=>execute(async()=>{
 if(!compareFirst||!compareLast||compareFirst===compareLast)
 throw Error("Selecciona dos ensayos cronológicos");
 const data=await get("?mode=COMPARE&earlier="+
 encodeURIComponent(compareFirst)+"&later="+
 encodeURIComponent(compareLast)) as{
 comparison:RecoveryRehearsalDiff};
 setComparison(data.comparison);setTab("COMPARISON");
 setNotice("Comparación de gates locales registrada.");
 });
 const exportRun=(format:"JSON"|"CSV"|"MARKDOWN")=>execute(async()=>{
 if(!selected)throw Error("Selecciona un ensayo");
 const result=await get("?mode=EXPORT&id="+
 encodeURIComponent(selected)+"&format="+format) as{
 artifact:{filename:string;mime:string;content:string}};
 download(result.artifact);
 setNotice("Informe exportado sin restauración ni autorización LIVE.");
 });
 const selectedRun=inventory?.entries.find(x=>x.id===selected);
 const filtered=useMemo(()=>(inventory?.entries??[]).filter(x=>
 statusFilter==="ALL"||x.status===statusFilter),[inventory,statusFilter]);
 return <div>
 <section style={card}>
 <h2>Ensayos auditables de recuperación de informes</h2>
 <p>Este módulo verifica y reproduce en memoria artefactos JSON
 guardados. No ejecuta restauración de PostgreSQL, no recupera
 datos de proveedores y no concede aceptación de clientes.</p>
 <div style={flex}>
 <button style={button} disabled={busy} onClick={load}>
 Consultar ensayos</button>
 <button style={button} disabled={busy}
 onClick={loadMatrix}>Evaluar matriz de capturas</button>
 <button style={button} disabled={!canWrite||busy||!chosen.length}
 onClick={run}>Registrar ensayo con selección</button>
 </div>
 {busy&&<p role="status">Validando integridad y procedencia…</p>}
 {error&&<p role="alert">{error}</p>}
 {notice&&<p role="status">{notice}</p>}
 </section>
 {inventory&&<>
 <section style={card}>
 <div style={flex}>
 <Stat name="Ensayos" value={inventory.summary.total}/>
 <Stat name="PASS offline" value={inventory.summary.passed}/>
 <Stat name="Bloqueados" value={inventory.summary.blocked}/>
 <Stat name="Incompletos" value={inventory.summary.incomplete}/>
 <Stat name="Incidencias" value={inventory.summary.issues}/>
 </div>
 {inventory.truncated&&<p role="alert">
 Hay más ensayos almacenados de los que caben en esta vista.</p>}
 <div style={flex}>{(["RUNS","SELECT","MATRIX","GATES",
 "AUDIT","COMPARISON"] as Tab[]).map(x=>
 <button key={x} style={{...button,fontWeight:tab===x?750:400}}
 onClick={()=>setTab(x)}>{x}</button>)}</div>
 </section>
 {tab==="MATRIX"&&<section style={card}>
 <h3>Último corte por tipo y aceptación offline</h3>
 {!matrix?<p>Consulta primero la matriz de fuentes.</p>:<>
 {matrix.matrix.map(x=><article key={x.kind} style={card}>
 <h4>{x.kind}</h4>
 <p>Capturas disponibles: {x.availableCaptures} ·
 fuente completa: {String(x.latestSourceComplete)} ·
 digest local verificado: {String(x.localDigestVerified)}</p>
 <p>Corte más reciente: {x.selectedCaptureId??"No existe"}</p>
 </article>)}
 <p>Tipos pendientes: {
 matrix.requiredKindsMissing.join(", ")||"Ninguno"}</p>
 <p>Ensayo preliminar bloqueado: {String(matrix.blocking)}</p>
 <p><strong>Restauración SQL real realizada: NO.</strong></p>
 </>}
 </section>}
 {tab==="SELECT"&&<section style={card}>
 <h3>Política del ensayo local</h3>
 <p>La selección se construye desde la matriz del servidor,
 no desde informes inventados por el navegador.</p>
 <button style={button} onClick={loadMatrix} disabled={busy}>
 Obtener últimos cortes</button>
 <p>IDs de capturas seleccionadas: {chosen.length}</p>
 <ul>{chosen.map(x=><li key={x}><code>{x}</code></li>)}</ul>
 <div style={flex}>
 <label>Máxima antigüedad (días){" "}
 <input type="number" min={1} max={3650} value={maxAge}
 onChange={e=>setMaxAge(Number(e.target.value))}/></label>
 <label><input type="checkbox" checked={strict}
 onChange={e=>setStrict(e.target.checked)}/>
 Bloquear fuentes incompletas</label>
 <label><input type="checkbox" checked={requireLinks}
 onChange={e=>setRequireLinks(e.target.checked)}/>
 Comprobar linaje entre informes</label>
 <label><input type="checkbox" checked={requireUnique}
 onChange={e=>setRequireUnique(e.target.checked)}/>
 Bloquear tipos duplicados</label>
 </div>
 <p>Desactivar una exigencia permite ver el ensayo en desarrollo,
 pero nunca convierte el resultado en aceptación LIVE.</p>
 <button style={button} disabled={busy||!canWrite||!chosen.length}
 onClick={run}>Ejecutar comprobación y registrar resultado</button>
 </section>}
 {tab==="RUNS"&&<section style={card}>
 <h3>Histórico de ensayos</h3>
 <label>Estado{" "}<select value={statusFilter}
 onChange={e=>setStatusFilter(e.target.value)}>
 <option value="ALL">Todos</option>
 {["PASS","BLOCKED","INCOMPLETE"].map(x=>
 <option key={x} value={x}>{x}</option>)}
 </select></label>
 <ol>{filtered.slice(0,limit).map(x=><li key={x.id}>
 <button style={button} onClick={()=>{
 setSelected(x.id);setTab("GATES");}}>
 {x.status} · {x.createdAt}</button>
 <p>{x.selectedCaptures} capturas ·
 {x.blockedGates} bloqueos · {x.unverifiableGates} externos no verificados</p>
 </li>)}</ol>
 {filtered.length>limit&&<button style={button}
 onClick={()=>setLimit(x=>x+25)}>Mostrar más</button>}
 </section>}
 {tab==="GATES"&&<section style={card}>
 <h3>Gates y pruebas de integridad del corte</h3>
 {!selectedRun?<p>Selecciona un ensayo en el histórico.</p>:<>
 <p>Digest: <code style={{overflowWrap:"anywhere"}}>{
 selectedRun.digest}</code></p>
 <p>Estado: {selectedRun.status}</p>
 <p>Reproducción JSON en memoria:
 {selectedRun.report.overview.reportsReplayedReadOnly} artefactos.</p>
 <label><input type="checkbox" checked={showWarnings}
 onChange={e=>setShowWarnings(e.target.checked)}/>
 Mostrar gates no verificables en offline</label>
 {selectedRun.report.gates.filter(x=>showWarnings||
 x.status==="PASS"||x.status==="BLOCK").map((x,i)=>
 <Gate key={x.id+"-"+i} gate={x}/>)}
 <div style={flex}>{(["JSON","CSV","MARKDOWN"] as const).map(x=>
 <button key={x} style={button} disabled={busy}
 onClick={()=>exportRun(x)}>Exportar {x}</button>)}</div>
 <p><strong>Restauraciones reales de base de datos: 0.</strong></p>
 </>}
 </section>}
 {tab==="AUDIT"&&<section style={card}>
 <h3>Diferencias entre integridad local y recuperación SQL</h3>
 <p>PASS comprueba hashes y relectura del contenido archivado.
 No equivale a restauración de una base PostgreSQL.</p>
 <p>Una recuperación real exige el workflow independiente
 de backup/restore y sus verificaciones.</p>
 <p>Gates de autorización LIVE y recuperación SQL
 permanecen NOT_VERIFIED en este módulo.</p>
 <p>No se inventan aprobaciones de clientes ni se modifican
 configuraciones reales de Microsoft/Google.</p>
 </section>}
 {tab==="COMPARISON"&&<section style={card}>
 <h3>Comparar dos ensayos</h3>
 <div style={flex}>
 <label>Anterior{" "}<select value={compareFirst}
 onChange={e=>setCompareFirst(e.target.value)}>
 <option value="">Seleccionar</option>
 {inventory.entries.map(x=><option value={x.id} key={x.id}>
 {x.createdAt} · {x.status}</option>)}
 </select></label>
 <label>Posterior{" "}<select value={compareLast}
 onChange={e=>setCompareLast(e.target.value)}>
 <option value="">Seleccionar</option>
 {inventory.entries.map(x=><option value={x.id} key={x.id}>
 {x.createdAt} · {x.status}</option>)}
 </select></label>
 </div>
 <button style={button} disabled={busy||!compareFirst||!compareLast}
 onClick={compare}>Comparar verificación</button>
 {comparison&&<div style={card}>
 <p>Gates corregidos: {comparison.fixedGateIds.join(", ")||"Ninguno"}</p>
 <p>Gates nuevos con errores:
 {comparison.newFailures.join(", ")||"Ninguno"}</p>
 <p>Δ capturas: {comparison.selectedCaptureChange}</p>
 <p>Estado cambiado: {String(comparison.readyStateChanged)}</p>
 <p>Datos reales restaurados: <strong>NO</strong></p>
 </div>}
 </section>}
 </>}
 </div>;
}
