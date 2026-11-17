"use client";
import{useMemo,useState}from "react";
import type{TrendReport,TrendPoint,TrendPair,
 TrendFinding,TrendSourceClass}from "../lib/offline-longitudinal-trends";
type Envelope={report:TrendReport;
 plan:{recommendations:Array<{id:string;urgency:string;
 category:string;rationale:string;nextCheck:string}>;
 summary:{blocks:number;reviews:number;tracking:number}};
 providerCalls:0;
 v1Writes:0;customerImprovementCertified:false};
type View="HISTORY"|"PAIRS"|"OPERATIONS"|"LIMITATIONS"|"INTEGRITY";
const views:View[]=["HISTORY","PAIRS","OPERATIONS","LIMITATIONS","INTEGRITY"];
const card:React.CSSProperties={border:"1px solid #94a3b866",
 borderRadius:12,padding:18,marginBottom:16};
const flex:React.CSSProperties={display:"flex",gap:12,
 flexWrap:"wrap",alignItems:"center"};
const button:React.CSSProperties={padding:"8px 12px",
 border:"1px solid #64748b88",borderRadius:8,cursor:"pointer",
 color:"inherit",background:"transparent"};
function Stat({title,value,hint}:{title:string;value:number|string;
 hint?:string}){return <div style={{...card,flex:"1 1 145px",minWidth:125}}>
 <small>{title}</small><p style={{fontSize:24,fontWeight:750}}>
 {value}</p>{hint&&<small>{hint}</small>}</div>;}
function safeScore(score:number|null){return score===null?"No evaluable":score;}
function TrendPointCard({point,selected,onSelect}:{
 point:TrendPoint;selected:boolean;onSelect:()=>void;
}){return <article style={card}>
 <div style={flex}><h3>Snapshot {point.snapshotId}</h3>
 <button style={button} onClick={onSelect}>
 {selected?"Ocultar":"Trazabilidad"}</button></div>
 <p>{point.evaluatedAt} · {point.modelId} rev {point.modelRevision}</p>
 <p>Origen: <strong>{point.sourceKind}</strong> / {
 point.sourceClass}</p>
 <div style={flex}>
 <Stat title="Score guardado" value={safeScore(point.score)}/>
 <Stat title="Cobertura guardada" value={point.coveragePercent+"%"}/>
 <Stat title="Controles verificados en registro"
 value={point.verifiedControls}/>
 <Stat title="Controles totales" value={point.totalControls}/>
 </div>
 <p>Estado original: {point.status}</p>
 {selected&&<div>
 <p>Digest de manifiesto:
 <code style={{overflowWrap:"anywhere"}}>{point.manifestDigest}</code></p>
 <p>Digest de informe:
 <code style={{overflowWrap:"anywhere"}}>{point.reportDigest}</code></p>
 <p>Scope LIVE autenticado por esta lectura: <strong>NO</strong></p>
 <p>Postura de seguridad certificada: <strong>NO</strong></p>
 </div>}
 </article>;}
function TrendPairCard({pair}:{
 pair:TrendPair;
}){return <article style={card}>
 <h3>{pair.earlierId} → {pair.laterId}</h3>
 <p>Comparabilidad: <strong>{pair.comparisonClass}</strong></p>
 <p>{pair.from} → {pair.to}</p>
 {pair.comparable?<div style={flex}>
 <Stat title="Δ score guardado"
 value={pair.scoreDelta===null?"No comparable":pair.scoreDelta}/>
 <Stat title="Δ cobertura" value={
 pair.coverageDelta===null?"No comparable":
 pair.coverageDelta+" pp"}/>
 <Stat title="Δ controles verificados"
 value={pair.verifiedControlsDelta??"No comparable"}/>
 <Stat title="Δ puntos de riesgo"
 value={pair.riskPointDelta??"No comparable"}/>
 </div>:<p>Los snapshots no pueden compararse directamente.</p>}
 <h4>Limitaciones de la comparación</h4>
 <ul>{pair.reasonCodes.map(x=><li key={x}>{x}</li>)}</ul>
 <p><strong>Mejora real de seguridad demostrada: NO.</strong></p>
 </article>;}
function TrendFindingRow({item}:{
 item:TrendFinding;
}){return <article style={card}>
 <p><strong>{item.severity}: {item.code}</strong></p>
 <p>{item.description}</p>
 {item.snapshotIds.length>0&&<p>Snapshots:
 {item.snapshotIds.join(", ")}</p>}
 </article>;}
function download(artifact:{filename:string;mime:string;content:string}){
 if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
 throw Error("Nombre de exportación inválido");
 const url=URL.createObjectURL(new Blob([artifact.content],
 {type:artifact.mime}));
 const anchor=document.createElement("a");
 anchor.href=url;anchor.download=artifact.filename;
 document.body.append(anchor);anchor.click();anchor.remove();
 URL.revokeObjectURL(url);
}
export function OfflineTrendWorkspace({slug,organizationId}:{
 slug:string;organizationId:string;
}){
 const [report,setReport]=useState<TrendReport|null>(null);
 const [plan,setPlan]=useState<Envelope["plan"]|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState("");
 const [notice,setNotice]=useState(""),[view,setView]=useState<View>("HISTORY");
 const [source,setSource]=useState("ALL"),[model,setModel]=useState("ALL");
 const [status,setStatus]=useState("ALL"),[from,setFrom]=useState("");
 const [to,setTo]=useState(""),[comparableOnly,setComparableOnly]=useState(false);
 const [showNull,setShowNull]=useState(true);
 const [selected,setSelected]=useState("");
 const [findingsLevel,setFindingsLevel]=useState("ALL");
 const [page,setPage]=useState(0),[pageSize,setPageSize]=useState(20);
 const endpoint="/api/organizations/"+encodeURIComponent(slug)+"/offline-trends";
 const load=async()=>{
 if(busy)return;setBusy(true);setError("");setNotice("");
 try{
 const res=await fetch(endpoint,{cache:"no-store"});
 const body=await res.json() as Partial<Envelope>;
 if(!res.ok||body.providerCalls!==0||body.v1Writes!==0||
 body.customerImprovementCertified!==false||
 body.report?.organizationId!==organizationId||
 body.report.schema!=="cyberpilot.offline.longitudinal.v1"||
 body.report.customerRiskReductionCertified!==false)
 throw Error("El historial no cumple el contrato de seguridad");
 setReport(body.report);setPlan(body.plan??null);
 setView("HISTORY");setPage(0);
 setNotice("Historial reconstruido desde snapshots v2 y eventos de acciones.");
 }catch(cause){setError(cause instanceof Error?cause.message:
 "Lectura histórica fallida");setReport(null);}
 finally{setBusy(false);}
 };
 const exportFile=async(format:"JSON"|"CSV"|"MARKDOWN")=>{
 if(!report||busy)return;setBusy(true);setError("");setNotice("");
 try{
 const res=await fetch(endpoint+"?format="+format,{cache:"no-store"});
 const body=await res.json();
 if(!res.ok||body.providerCalls!==0||body.v1Writes!==0||
 body.customerImprovementCertified!==false||!body.artifact)
 throw Error("Exportación denegada");
 download(body.artifact);
 setNotice("Historia exportada sin modificar CyberScore v1.");
 }catch(cause){setError(cause instanceof Error?cause.message:
 "Exportación fallida");}
 finally{setBusy(false);}
 };
 const kinds:TrendSourceClass[]=["SYNTHETIC","OFFLINE","LAB",
 "LIVE_LABEL","DECLARED","UNKNOWN"];
 const models=useMemo(()=>[...new Set(report?.points.map(x=>x.modelId)??[])].sort(),[report]);
 const states=useMemo(()=>[...new Set(report?.points.map(x=>x.status)??[])].sort(),[report]);
 const points=useMemo(()=>{
 const paired=new Set((report?.pairs??[]).filter(x=>x.comparable)
 .flatMap(x=>[x.earlierId,x.laterId]));
 return(report?.points??[]).filter(x=>
 (source==="ALL"||source===x.sourceKind)&&
 (model==="ALL"||model===x.modelId)&&
 (status==="ALL"||status===x.status)&&
 (!from||x.evaluatedAt.slice(0,10)>=from)&&
 (!to||x.evaluatedAt.slice(0,10)<=to)&&
 (!comparableOnly||paired.has(x.snapshotId))&&
 (showNull||x.score!==null));
 },[report,source,model,status,from,to,comparableOnly,showNull]);
 const pairRows=useMemo(()=>report?.pairs??[],[report]);
 const issues=useMemo(()=>(report?.findings??[]).filter(x=>
 findingsLevel==="ALL"||x.severity===findingsLevel),[report,findingsLevel]);
 const fromIndex=page*pageSize;
 return <div>
 <section style={card}>
 <h2>Comparación temporal de evaluaciones persistidas</h2>
 <p>Compara snapshots del mismo modelo, revisión y origen
 solo cuando conservan controles equivalentes. Una variación
 numérica no significa mejora verificada de un cliente.</p>
 <div style={flex}>
 <button style={button} disabled={busy}
 onClick={load}>Consultar historial PostgreSQL</button>
 <button style={button} disabled={!report||busy}
 onClick={()=>exportFile("JSON")}>Exportar JSON</button>
 <button style={button} disabled={!report||busy}
 onClick={()=>exportFile("CSV")}>Exportar CSV</button>
 <button style={button} disabled={!report||busy}
 onClick={()=>exportFile("MARKDOWN")}>Exportar informe</button>
 </div>
 {busy&&<p role="status">Conciliando revisiones históricas…</p>}
 {error&&<p role="alert">{error}</p>}
 {notice&&<p role="status">{notice}</p>}
 </section>
 {report&&<>
 <section style={card}>
 <h3>Estado histórico: {report.outcome}</h3>
 <p>Fecha de consulta: {report.evaluatedAt}</p>
 {report.outcome==="INCOMPLETE"&&<p role="alert">
 Se ha detectado auditoría incompleta o datos truncados.
 No extraer conclusiones sobre tendencias.</p>}
 <div style={flex}>
 <Stat title="Snapshots" value={report.summary.snapshots}/>
 <Stat title="Comparaciones compatibles"
 value={report.summary.comparablePairs}/>
 <Stat title="Comparaciones bloqueadas"
 value={report.summary.incomparablePairs}/>
 <Stat title="Origen sintético" value={report.summary.syntheticSnapshots}/>
 <Stat title="Etiquetas LIVE sin revalidar"
 value={report.summary.liveLabelsNotAuthenticated}/>
 <Stat title="Scores nulos" value={report.summary.nullScores}/>
 </div>
 <div style={flex}>{views.map(x=><button key={x}
 style={{...button,fontWeight:view===x?700:400}}
 onClick={()=>setView(x)}>{x}</button>)}</div>
 </section>
 {view==="HISTORY"&&<section style={card}>
 <h3>Snapshots históricos guardados</h3>
 <div style={flex}>
 <label>Origen{" "}<select value={source}
 onChange={e=>{setSource(e.target.value);setPage(0);}}>
 <option value="ALL">Todos</option>
 {kinds.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Modelo{" "}<select value={model}
 onChange={e=>{setModel(e.target.value);setPage(0);}}>
 <option value="ALL">Todos</option>
 {models.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Estado{" "}<select value={status}
 onChange={e=>setStatus(e.target.value)}>
 <option value="ALL">Todos</option>
 {states.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Desde{" "}<input type="date" value={from}
 onChange={e=>setFrom(e.target.value)}/></label>
 <label>Hasta{" "}<input type="date" value={to}
 onChange={e=>setTo(e.target.value)}/></label>
 </div>
 <div style={flex}>
 <label><input type="checkbox" checked={comparableOnly}
 onChange={e=>setComparableOnly(e.target.checked)}/>
 Solo snapshots de parejas compatibles</label>
 <label><input type="checkbox" checked={showNull}
 onChange={e=>setShowNull(e.target.checked)}/>
 Incluir evaluaciones sin score</label>
 </div>
 <p>{points.length} snapshots visibles.</p>
 {points.slice(fromIndex,fromIndex+pageSize).map(x=>
 <TrendPointCard key={x.snapshotId} point={x}
 selected={selected===x.snapshotId}
 onSelect={()=>setSelected(v=>v===x.snapshotId?"":x.snapshotId)}/>)}
 {!points.length&&<p>No hay evaluaciones persistidas compatibles
 con los filtros; esto no acredita seguridad.</p>}
 <div style={flex}>
 <button style={button} disabled={page===0}
 onClick={()=>setPage(x=>x-1)}>Anterior</button>
 <span>Página {page+1}</span>
 <button style={button} disabled={fromIndex+pageSize>=points.length}
 onClick={()=>setPage(x=>x+1)}>Siguiente</button>
 <label>Tamaño{" "}<select value={pageSize}
 onChange={e=>{setPageSize(Number(e.target.value));setPage(0);}}>
 {[10,20,50].map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 </div>
 </section>}
 {view==="PAIRS"&&<section style={card}>
 <h3>Comparabilidad entre cortes adyacentes</h3>
 <p>Se rechaza la comparación cuando cambia el modelo,
 revisión, tipo de fuente, número de controles o un score
 permanece nulo.</p>
 {pairRows.map((x,i)=><TrendPairCard
 key={x.earlierId+"-"+x.laterId+"-"+i} pair={x}/>)}
 {pairRows.length===0&&<p>No existen pares adyacentes
 comparables dentro de los registros guardados.</p>}
 </section>}
 {view==="OPERATIONS"&&<section style={card}>
 <h3>Pulso del seguimiento de riesgos</h3>
 <p>Se calcula desde el estado actual y eventos CAS
 persistidos. No sustituye una historia de snapshots de acciones.</p>
 <div style={flex}>
 <Stat title="Acciones" value={report.actionPulse.total}/>
 <Stat title="En curso" value={report.actionPulse.active}/>
 <Stat title="Bloqueadas" value={report.actionPulse.blocked}/>
 <Stat title="Completadas declaradas"
 value={report.actionPulse.reportedDone}/>
 <Stat title="Sin asignación"
 value={report.actionPulse.unassigned}/>
 <Stat title="Vencidas"
 value={report.actionPulse.expiredDue}/>
 </div>
 <p>Eventos auditados: {report.actionPulse.events} ·
 cadenas inválidas: {report.actionPulse.invalidEventChains}.</p>
 <p><strong>Remediaciones verificadas en proveedor: 0.</strong></p>
 </section>}
 {view==="LIMITATIONS"&&<section style={card}>
 <h3>Incidencias de comparabilidad</h3>
 {plan&&<article style={card}>
 <h4>Plan de revisión histórica</h4>
 <p>Bloqueos: {plan.summary.blocks} · revisiones:
 {plan.summary.reviews} · seguimiento: {plan.summary.tracking}.</p>
 {plan.recommendations.map(x=><p key={x.id}>
 <strong>{x.urgency}: {x.category}</strong> ·
 {x.rationale} Próximo control: {x.nextCheck}</p>)}
 <p>Las recomendaciones no constituyen aceptación operativa.</p>
 </article>}
 <label>Gravedad{" "}<select value={findingsLevel}
 onChange={e=>setFindingsLevel(e.target.value)}>
 <option value="ALL">Todas</option>
 {["BLOCK","WARNING","INFO"].map(x=>
 <option key={x} value={x}>{x}</option>)}
 </select></label>
 {issues.map((x,i)=><TrendFindingRow key={x.code+"-"+i} item={x}/>)}
 {!issues.length&&<p>Sin incidencias adicionales detectadas;
 no significa certificación de seguridad.</p>}
 </section>}
 {view==="INTEGRITY"&&<section style={card}>
 <h3>Contrato de procedencia y coherencia histórica</h3>
 <p>Digest local:
 <code style={{overflowWrap:"anywhere"}}>{report.reportDigest}</code></p>
 <p>Ventana fuente completa: {String(report.sourceComplete)} ·
 origen tenant correcto: {String(report.scopeValid)}</p>
 <p>Versiones de modelo distintas:
 {report.summary.v2ModelRevisions}</p>
 <p>Última evaluación: {report.summary.latestSnapshotId??"No hay"}</p>
 <p>Score almacenado: {
 report.summary.latestStoredScore??"No evaluable"}</p>
 <p>Modelo v1 modificado: <strong>NO</strong></p>
 <p>Tenant LIVE autenticado: <strong>NO</strong></p>
 <p>Mejora de seguridad certificada: <strong>NO</strong></p>
 </section>}
 </>}
 </div>;
}
