"use client";
import{useMemo,useState}from "react";
import type{OfflineCaptureKind,CaptureIntegrityManifest,
 CaptureDiff}from "../lib/offline-report-capture-domain";
type Summary={
 id:string;organizationId:string;kind:OfflineCaptureKind;
 schemaVersion:string;originalDigest:string;payloadDigest:string;
 sourceComplete:boolean;createdAt:string;createdById:string;
 externalAttestation:false;customerCertification:false;
};
type ListData={
 organizationId:string;sourceTruncated:boolean;captures:Summary[];
 validations:Array<{id:string;valid:boolean;errors:string[]}>;
 manifest:CaptureIntegrityManifest;
 stats:{total:number;complete:number;incomplete:number;
 invalid:number;kindCounts:Record<OfflineCaptureKind,number>};
};
type Envelope={data:ListData;providerCalls:0;customerCertified:false;
 backupRestorePerformed:false;scoreV1Writes:0};
type View="INVENTORY"|"NEW"|"COMPARE"|"AUDIT"|"DETAIL";
const kinds:OfflineCaptureKind[]=[
 "INTEGRATED_RISKS","EVIDENCE_DECISIONS","EXECUTIVE","LONGITUDINAL"];
const card:React.CSSProperties={
 border:"1px solid #94a3b866",borderRadius:12,padding:18,marginBottom:16};
const action:React.CSSProperties={
 border:"1px solid #64748b88",background:"transparent",color:"inherit",
 borderRadius:8,padding:"8px 12px",cursor:"pointer"};
const row:React.CSSProperties={display:"flex",gap:12,
 flexWrap:"wrap",alignItems:"center"};
function Metric({name,value}:{name:string;value:number|string}){
 return <div style={{...card,minWidth:140,flex:"1 1 140px"}}>
 <small>{name}</small><p style={{fontSize:24,fontWeight:750}}>
 {value}</p></div>;
}
function download(artifact:{filename:string;mime:string;content:string}){
 if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
 throw Error("Archivo no permitido");
 const url=URL.createObjectURL(new Blob([artifact.content],
 {type:artifact.mime}));
 const a=document.createElement("a");a.href=url;
 a.download=artifact.filename;document.body.append(a);
 a.click();a.remove();URL.revokeObjectURL(url);
}
export function OfflineCaptureWorkspace({slug,organizationId,canWrite}:{
 slug:string;organizationId:string;canWrite:boolean;
}){
 const [inventory,setInventory]=useState<ListData|null>(null);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState(""),[notice,setNotice]=useState("");
 const [view,setView]=useState<View>("INVENTORY");
 const [kind,setKind]=useState<OfflineCaptureKind>("INTEGRATED_RISKS");
 const [strict,setStrict]=useState(false);
 const [filter,setFilter]=useState("ALL");
 const [onlyComplete,setOnlyComplete]=useState(false);
 const [showInvalid,setShowInvalid]=useState(false);
 const [selected,setSelected]=useState("");
 const [earlier,setEarlier]=useState(""),[later,setLater]=useState("");
 const [comparison,setComparison]=useState<CaptureDiff|null>(null);
 const [detail,setDetail]=useState<unknown>(null);
 const [audit,setAudit]=useState<unknown>(null);
 const [limit,setLimit]=useState(30);
 const endpoint="/api/organizations/"+encodeURIComponent(slug)+
 "/offline-captures";
 const execute=async(task:()=>Promise<void>)=>{
 if(busy)return;setBusy(true);setError("");setNotice("");
 try{await task();}
 catch(e){setError(e instanceof Error?e.message:"Error de captura");}
 finally{setBusy(false);}
 };
 const get=async(suffix="")=>{
 const res=await fetch(endpoint+suffix,{cache:"no-store"});
 const payload=await res.json() as Partial<Envelope>;
 if(!res.ok||payload.providerCalls!==0||
 payload.customerCertified!==false||
 payload.backupRestorePerformed!==false||payload.scoreV1Writes!==0)
 throw Error("Corte no autorizado o respuesta incompleta");
 return payload.data;
 };
 const refresh=async()=>{
 const data=await get() as ListData;
 if(data.organizationId!==organizationId)
 throw Error("Corte perteneciente a otra organización");
 setInventory(data);
 };
 const load=()=>execute(async()=>{
 await refresh();setView("INVENTORY");
 setNotice("Inventario persistido reconciliado con PostgreSQL.");
 });
 const capture=()=>execute(async()=>{
 if(!canWrite)throw Error("Rol sin permiso para capturar");
 const res=await fetch(endpoint,{method:"POST",cache:"no-store",
 headers:{"Content-Type":"application/json"},
 body:JSON.stringify({kind,strictComplete:strict})});
 const payload=await res.json() as Record<string,unknown>;
 if(!res.ok)throw Error(typeof payload.code==="string"?
 payload.code:"Captura rechazada");
 if(payload.providerCalls!==0||payload.customerCertified!==false||
 payload.scoreV1Writes!==0||payload.backupRestorePerformed!==false)
 throw Error("La respuesta del corte es insegura");
 await refresh();setView("INVENTORY");
 setNotice("Corte preservado con digest; no se ha generado certificación.");
 });
 const compare=()=>execute(async()=>{
 if(!earlier||!later||earlier===later)
 throw Error("Selecciona dos cortes diferentes y ordenados");
 const data=await get("?mode=COMPARE&earlier="+
 encodeURIComponent(earlier)+"&later="+encodeURIComponent(later));
 if(!data||typeof data!=="object"||
 !("comparison" in data))throw Error("Comparación no evaluable");
 setComparison(data.comparison as CaptureDiff);
 setNotice("Comparación limitada a registros de esquema compatible.");
 });
 const readDetail=(id:string)=>execute(async()=>{
 const data=await get("?mode=DETAIL&id="+encodeURIComponent(id));
 setSelected(id);setDetail(data);setView("DETAIL");
 setNotice("Se ha verificado la integridad del corte guardado.");
 });
 const auditInventory=()=>execute(async()=>{
 const data=await get("?mode=AUDIT");
 setAudit(data);setView("AUDIT");
 setNotice("Inventario revisado sin ejecutar recuperación SQL.");
 });
 const exportFile=(format:"JSON"|"CSV"|"MARKDOWN")=>execute(async()=>{
 const data=await get("?mode=EXPORT&format="+format);
 if(!data||typeof data!=="object"||!("artifact" in data))
 throw Error("No existe el artefacto exportable");
 download(data.artifact as {filename:string;mime:string;content:string});
 setNotice("Artefacto exportado sin ejecutar proveedor externo.");
 });
 const filtered=useMemo(()=>(inventory?.captures??[]).filter(x=>
 (filter==="ALL"||x.kind===filter)&&
 (!onlyComplete||x.sourceComplete)&&
 (!showInvalid||inventory?.validations.some(v=>
 v.id===x.id&&!v.valid))
 ),[inventory,filter,onlyComplete,showInvalid]);
 const manifest=inventory?.manifest;
 const selectedRecord=inventory?.captures.find(x=>x.id===selected);
 return <div>
 <section style={card}>
 <h2>Capturas inmutables de informes offline</h2>
 <p>Los cortes se generan desde datos de servidor, no desde JSON
 arbitrario enviado por el navegador. Cada fuente se verifica
 antes de persistirla. SHA-256 protege integridad local, no
 autenticación de un cliente LIVE.</p>
 <div style={row}>
 <button style={action} disabled={busy} onClick={load}>
 Consultar cortes</button>
 <button style={action} disabled={busy||!canWrite}
 onClick={()=>setView("NEW")}>Crear corte</button>
 <button style={action} disabled={busy} onClick={auditInventory}>
 Auditar integridad</button>
 {(["JSON","CSV","MARKDOWN"] as const).map(x=>
 <button style={action} key={x} disabled={busy||!inventory}
 onClick={()=>exportFile(x)}>Exportar {x}</button>)}
 </div>
 {busy&&<p role="status">Evaluando archivos guardados…</p>}
 {error&&<p role="alert">{error}</p>}
 {notice&&<p role="status">{notice}</p>}
 </section>
 {inventory&&<>
 <section style={card}>
 <div style={row}>
 <Metric name="Capturas" value={inventory.stats.total}/>
 <Metric name="Completas según fuente" value={inventory.stats.complete}/>
 <Metric name="Incompletas" value={inventory.stats.incomplete}/>
 <Metric name="Dañadas" value={inventory.stats.invalid}/>
 <Metric name="Tipos" value={kinds.filter(x=>
 inventory.stats.kindCounts[x]>0).length}/>
 </div>
 {inventory.sourceTruncated&&<p role="alert">
 Se alcanzó el límite de captura; el inventario puede estar incompleto.</p>}
 <p>Manifiesto local: <code style={{overflowWrap:"anywhere"}}>
 {manifest?.digest}</code></p>
 <p>Listo para ensayo de desarrollo: {
 String(manifest?.readyForDevelopmentRehearsal??false)}</p>
 <p>Listo para aprobación LIVE: <strong>NO</strong>.</p>
 <div style={row}>{(["INVENTORY","NEW","COMPARE","AUDIT","DETAIL"] as View[]).map(x=><button key={x}
 style={{...action,fontWeight:view===x?750:400}}
 onClick={()=>setView(x)}>{x}</button>)}</div>
 </section>
 {view==="NEW"&&<section style={card}>
 <h3>Crear un corte inmutable nuevo</h3>
 <p>Los cortes se calculan en el servidor leyendo PostgreSQL
 con aislamiento por organización y sin tocar CyberScore v1.</p>
 <label>Origen{" "}<select value={kind}
 onChange={e=>setKind(e.target.value as OfflineCaptureKind)}>
 {kinds.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label><input type="checkbox" checked={strict}
 onChange={e=>setStrict(e.target.checked)}/>
 Rechazar si las fuentes están incompletas</label>
 <p>Los informes con fuentes incompletas se pueden archivar con
 sus limitaciones salvo que exijas cobertura completa.</p>
 <button style={action} disabled={busy||!canWrite}
 onClick={capture}>Guardar corte auditado</button>
 </section>}
 {view==="INVENTORY"&&<section style={card}>
 <h3>Historial de cortes</h3>
 <div style={row}>
 <label>Tipo{" "}<select value={filter}
 onChange={e=>setFilter(e.target.value)}>
 <option value="ALL">Todos</option>
 {kinds.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label><input type="checkbox" checked={onlyComplete}
 onChange={e=>setOnlyComplete(e.target.checked)}/>
 Solo fuentes completas</label>
 <label><input type="checkbox" checked={showInvalid}
 onChange={e=>setShowInvalid(e.target.checked)}/>
 Solo anomalías</label>
 </div>
 <p>{filtered.length} capturas.</p>
 <ol>{filtered.slice(0,limit).map(x=><li key={x.id}>
 <button style={action} onClick={()=>readDetail(x.id)}>
 {x.kind} · {x.createdAt}</button>
 <p>{x.sourceComplete?"Fuente íntegra":"Fuente incompleta"} ·
 digest <code>{x.payloadDigest.slice(0,16)}</code></p>
 </li>)}</ol>
 {filtered.length>limit&&<button style={action}
 onClick={()=>setLimit(x=>x+30)}>Mostrar más</button>}
 </section>}
 {view==="COMPARE"&&<section style={card}>
 <h3>Comparación de cortes existentes</h3>
 <p>Solo se comparan cortes del mismo tenant, tipo y esquema.
 Una diferencia de conteos no acredita reducción de riesgo.</p>
 <div style={row}>
 <label>Anterior{" "}<select value={earlier}
 onChange={e=>setEarlier(e.target.value)}>
 <option value="">Seleccionar</option>
 {inventory.captures.map(x=><option key={x.id} value={x.id}>
 {x.kind} · {x.createdAt}</option>)}
 </select></label>
 <label>Posterior{" "}<select value={later}
 onChange={e=>setLater(e.target.value)}>
 <option value="">Seleccionar</option>
 {inventory.captures.map(x=><option key={x.id} value={x.id}>
 {x.kind} · {x.createdAt}</option>)}
 </select></label>
 </div>
 <button style={action} disabled={busy||!earlier||!later}
 onClick={compare}>Comparar cortes auditados</button>
 {comparison&&<section style={card}>
 <p>Tipo: {comparison.kind}</p>
 <p>Digest original cambiado:
 {String(comparison.originalDigestChanged)}</p>
 <p>Fuente completa en ambos: {
 String(comparison.sourceCompleteBoth)}</p>
 <p>Δ registros: {comparison.recordCountDelta??"No comparable"}</p>
 <p>Δ riesgos: {comparison.riskCountDelta??"No comparable"}</p>
 <p>Δ declarados: {
 comparison.declaredCompleteDelta??"No comparable"}</p>
 <p><strong>Mejora real demostrada: NO.</strong></p>
 </section>}
 </section>}
 {view==="DETAIL"&&<section style={card}>
 <h3>Integridad de corte seleccionado</h3>
 <p>ID: {selectedRecord?.id??selected}</p>
 <p>Tipo: {selectedRecord?.kind??"No consta"}</p>
 <p>Origen SHA-256: {selectedRecord?.originalDigest}</p>
 <p>Carga SHA-256: {selectedRecord?.payloadDigest}</p>
 <p>Autor: {selectedRecord?.createdById}</p>
 <p>Lectura verificada: {detail?"Disponible":"No cargada"}</p>
 <p>Ni la lectura ni la verificación restauran una base de datos.</p>
 </section>}
 {view==="AUDIT"&&<section style={card}>
 <h3>Auditoría de archivos persistidos</h3>
 <p>Capturas del manifiesto: {manifest?.entryCount}</p>
 <p>Integridad fallida: {manifest?.integrityFailures}</p>
 <p>Duplicados: {manifest?.duplicates}</p>
 <p>Orígenes incompletos: {manifest?.incompleteSources}</p>
 <p>Resultado de auditoría: {audit?"Consultado":"Sin consultar"}</p>
 <h4>Validación por archivo</h4>
 {inventory.validations.map(x=><p key={x.id}>
 <strong>{x.valid?"PASS":"BLOCK"}</strong> ·
 <code>{x.id}</code> · {x.errors.join(", ")||"sin anomalías"}
 </p>)}
 <p>El inventario se evalúa localmente, no autentica terceros.</p>
 </section>}
 </>}
 </div>;
}
