"use client";
import {useMemo,useState} from "react";
import type{SlaOperationalReport,SlaSignal,
 SlaOwnerWorkload,SlaActionRow}from "../lib/offline-action-sla";
type Envelope={report:SlaOperationalReport;providerCalls:0;
 notificationsSent:0;remediationsVerified:0};
type View="SIGNALS"|"OWNERS"|"ACTIONS"|"CALENDAR"|"INTEGRITY";
const views:View[]=["SIGNALS","OWNERS","ACTIONS","CALENDAR","INTEGRITY"];
const levels:SlaSignal["level"][]=["BLOCK","URGENT","WARNING","INFO"];
const card:React.CSSProperties={border:"1px solid #94a3b866",padding:18,
 borderRadius:12,marginBottom:16};
const button:React.CSSProperties={border:"1px solid #64748b88",
 background:"transparent",color:"inherit",borderRadius:8,
 padding:"8px 12px",cursor:"pointer"};
const flex:React.CSSProperties={display:"flex",gap:12,
 alignItems:"center",flexWrap:"wrap"};
function Stat({label,value,hint}:{label:string;value:number|string;
 hint?:string}){return <div style={{...card,minWidth:140,flex:"1 1 140px"}}>
 <small>{label}</small><p style={{fontSize:24,fontWeight:700}}>
 {value}</p>{hint&&<small>{hint}</small>}</div>;}
function levelColor(level:SlaSignal["level"]){
 return level==="BLOCK"?"#b91c1c":level==="URGENT"?"#b45309":
 level==="WARNING"?"#a16207":"#64748b";
}
function SignalDetail({signal,close}:{signal:SlaSignal;close:()=>void}){
 return <article style={card}>
 <div style={flex}><h3>{signal.code}</h3>
 <button style={button} onClick={close}>Cerrar</button></div>
 <p>{signal.description}</p>
 <p><strong>Siguiente intervención:</strong> {
 signal.recommendedAction}</p>
 <p>Acción: <code>{signal.actionId}</code></p>
 <p>Plazo: {signal.deadline??"No definido"} ·
 prioridad: {signal.priority} · estado: {signal.status}</p>
 <p>Minutos laborables vencidos: {
 signal.overdueBusinessMinutes===null?"No evaluable":
 signal.overdueBusinessMinutes}</p>
 <p>Responsable: {signal.ownerUserId??"Sin asignación"}</p>
 <p>Actores de eventos: {signal.actorRefs.join(", ")||"No consta"}</p>
 <p><strong>Notificación enviada: NO · Remediación verificada: NO</strong></p>
 </article>;
}
function OwnerCard({owner,onFilter}:{
 owner:SlaOwnerWorkload;onFilter:()=>void;
}){return <article style={card}>
 <div style={flex}>
 <h3>{owner.ownerUserId??"Sin responsable"}</h3>
 <button style={button} onClick={onFilter}>Ver señales</button>
 </div>
 <div style={flex}>
 <Stat label="Acciones" value={owner.total}/>
 <Stat label="Urgentes" value={owner.urgent}/>
 <Stat label="Bloqueadas" value={owner.blocked}/>
 <Stat label="Vencidas" value={owner.overdue}/>
 <Stat label="Excepciones" value={owner.exceptions}/>
 </div>
 <p>Última actividad más antigua: {
 owner.oldestActivity??"Sin datos"}</p>
 <p>Remediaciones verificadas externamente: 0.</p>
 </article>;}
function ActionCard({item,onFilter}:{
 item:SlaActionRow;onFilter:()=>void;
}){return <article style={card}>
 <div style={flex}><h3>{item.title}</h3>
 <button style={button} onClick={onFilter}>Ver señales</button></div>
 <p>{item.status} · {item.priority} ·
 incidente {item.riskKey.slice(0,12)} · revisión {item.revision}</p>
 <p>Responsable: {item.ownerUserId??"No asignado"}</p>
 <p>Primera respuesta: {item.responseDeadline??"No evaluable"}</p>
 <p>Finalización: {item.completionDeadline??"No evaluable"}</p>
 <p>Fecha interna acordada: {item.dueAt??"No definida"}</p>
 <p>Excepción hasta: {item.exceptionExpiresAt??"No existe"}</p>
 <p>Última actividad: {item.lastActivityAt}</p>
 <p>Señales asociadas: {item.signalKeys.length} ·
 nivel: {item.worstLevel}</p>
 <p><strong>Resolución técnica en proveedor: NO.</strong></p>
 </article>;}
function download(artifact:{filename:string;mime:string;content:string}){
 if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
 throw Error("Archivo inválido");
 const url=URL.createObjectURL(new Blob([artifact.content],
 {type:artifact.mime}));
 const a=document.createElement("a");a.href=url;
 a.download=artifact.filename;document.body.append(a);
 a.click();a.remove();URL.revokeObjectURL(url);
}
export function OfflineSlaWorkspace({slug,organizationId}:{
 slug:string;organizationId:string;
}){
 const [report,setReport]=useState<SlaOperationalReport|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState("");
 const [notice,setNotice]=useState(""),[view,setView]=useState<View>("SIGNALS");
 const [search,setSearch]=useState(""),[level,setLevel]=useState("ALL");
 const [code,setCode]=useState("ALL"),[owner,setOwner]=useState("ALL");
 const [priority,setPriority]=useState("ALL"),[status,setStatus]=useState("ALL");
 const [selected,setSelected]=useState(""),[limit,setLimit]=useState(25);
 const [onlyOverdue,setOnlyOverdue]=useState(false);
 const [includeInfo,setIncludeInfo]=useState(false);
 const [showWorkingDays,setShowWorkingDays]=useState(true);
 const endpoint="/api/organizations/"+encodeURIComponent(slug)+"/offline-sla";
 const load=async()=>{
 if(busy)return;setBusy(true);setError("");setNotice("");
 try{
 const res=await fetch(endpoint,{cache:"no-store"});
 const body=await res.json() as Partial<Envelope>;
 if(!res.ok||body.report?.organizationId!==organizationId||
 body.report.schema!=="cyberpilot.offline.sla.v1"||
 body.providerCalls!==0||body.notificationsSent!==0||
 body.remediationsVerified!==0||
 body.report.providerAutomationDisabled!==true)
 throw Error("La auditoría SLA no está disponible o resulta incoherente");
 setReport(body.report);setView("SIGNALS");setSelected("");
 setNotice("Plazos internos calculados desde los eventos persistidos.");
 }catch(cause){setReport(null);setError(cause instanceof Error?
 cause.message:"Error leyendo el seguimiento");}
 finally{setBusy(false);}
 };
 const exportFile=async(format:"JSON"|"CSV"|"MARKDOWN")=>{
 if(!report||busy)return;
 setBusy(true);setError("");setNotice("");
 try{
 const res=await fetch(endpoint+"?format="+format,{cache:"no-store"});
 const body=await res.json();
 if(!res.ok||body.providerCalls!==0||
 body.notificationsSent!==0||body.remediationsVerified!==0||
 !body.artifact)throw Error("La exportación no está autorizada");
 download(body.artifact);
 setNotice("Informe exportado sin avisos ni acciones externas.");
 }catch(cause){setError(cause instanceof Error?cause.message:"Error de descarga");}
 finally{setBusy(false);}
 };
 const codes=useMemo(()=>[...new Set(report?.signals.map(x=>x.code)??[])].sort(),[report]);
 const owners=useMemo(()=>report?.workloads.map(x=>x.ownerUserId??"NONE")??[],[report]);
 const signals=useMemo(()=>{
 const needle=search.toLowerCase().trim();
 return(report?.signals??[]).filter(x=>
 (level==="ALL"||x.level===level)&&
 (code==="ALL"||x.code===code)&&
 (owner==="ALL"||(owner==="NONE"&&x.ownerUserId===null)||
 x.ownerUserId===owner)&&
 (priority==="ALL"||x.priority===priority)&&
 (status==="ALL"||x.status===status)&&
 (!onlyOverdue||x.overdueBusinessMinutes!==null&&
 x.overdueBusinessMinutes>0)&&
 (includeInfo||x.level!=="INFO")&&
 (!needle||[x.code,x.description,x.actionId,
 x.recommendedAction].join(" ").toLowerCase().includes(needle)));
 },[report,search,level,code,owner,priority,status,
 onlyOverdue,includeInfo]);
 const actionRows=useMemo(()=>(report?.rows??[]).filter(x=>
 (status==="ALL"||x.status===status)&&
 (priority==="ALL"||x.priority===priority)&&
 (owner==="ALL"||(owner==="NONE"&&x.ownerUserId===null)||
 x.ownerUserId===owner)&&
 (!search||[x.title,x.riskKey,x.actionId].join(" ")
 .toLowerCase().includes(search.toLowerCase()))
 ),[report,search,status,priority,owner]);
 const chosen=signals.find(x=>x.key===selected);
 return <div>
 <section style={card}>
 <h2>Plazos y escalados de seguimiento</h2>
 <p>Objetivos de gestión interna basados en días y horas de
 trabajo configurados de forma explícita. No son plazos regulatorios,
 notificaciones reales ni remediaciones ejecutadas.</p>
 <div style={flex}>
 <button style={button} disabled={busy} onClick={load}>
 Evaluar seguimiento</button>
 <button style={button} disabled={!report||busy}
 onClick={()=>exportFile("JSON")}>JSON</button>
 <button style={button} disabled={!report||busy}
 onClick={()=>exportFile("CSV")}>CSV de alertas</button>
 <button style={button} disabled={!report||busy}
 onClick={()=>exportFile("MARKDOWN")}>Expediente</button>
 </div>
 {busy&&<p role="status">Evaluando eventos y vencimientos…</p>}
 {error&&<p role="alert">{error}</p>}
 {notice&&<p role="status">{notice}</p>}
 </section>
 {report&&<>
 <section style={card}>
 <h3>Estado: {report.state}</h3>
 <p>Evaluado: {report.asOf}</p>
 {report.state==="INCOMPLETE"&&<p role="alert">
 La cadena de eventos o su lectura no es completa: no
 debe considerarse superada la revisión técnica.</p>}
 <div style={flex}>
 <Stat label="Acciones" value={report.overview.totalActions}/>
 <Stat label="Sin asignación" value={report.overview.unowned}/>
 <Stat label="Respuesta tardía" value={report.overview.responseOverdue}/>
 <Stat label="Finalización tardía" value={report.overview.completionOverdue}/>
 <Stat label="Bloqueos" value={report.overview.blocked}/>
 <Stat label="Excepciones caducadas" value={report.overview.exceptionsExpired}/>
 </div>
 <div style={flex}>{views.map(x=><button key={x}
 style={{...button,fontWeight:x===view?700:400}}
 onClick={()=>setView(x)}>{x}</button>)}</div>
 </section>
 {(view==="SIGNALS"||view==="ACTIONS")&&
 <section style={card}>
 <h3>Filtros de operación</h3>
 <div style={flex}>
 <label>Buscar{" "}<input value={search}
 onChange={e=>setSearch(e.target.value)}/></label>
 <label>Responsable{" "}<select value={owner}
 onChange={e=>setOwner(e.target.value)}>
 <option value="ALL">Todos</option>
 {owners.map(x=><option key={x} value={x}>
 {x==="NONE"?"Sin asignación":x}</option>)}
 </select></label>
 <label>Prioridad{" "}<select value={priority}
 onChange={e=>setPriority(e.target.value)}>
 <option value="ALL">Todas</option>
 {["URGENT","HIGH","NORMAL","LOW"].map(x=>
 <option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Estado{" "}<select value={status}
 onChange={e=>setStatus(e.target.value)}>
 <option value="ALL">Todos</option>
 {["OPEN","IN_PROGRESS","BLOCKED","DONE_REPORTED",
 "EXCEPTION","REOPENED"].map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 </div>
 </section>}
 {view==="SIGNALS"&&<section style={card}>
 <h3>Alertas de gestión (no enviadas)</h3>
 <div style={flex}>
 <label>Nivel{" "}<select value={level}
 onChange={e=>setLevel(e.target.value)}>
 <option value="ALL">Todos</option>
 {levels.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Motivo{" "}<select value={code}
 onChange={e=>setCode(e.target.value)}>
 <option value="ALL">Todos</option>
 {codes.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label><input type="checkbox" checked={onlyOverdue}
 onChange={e=>setOnlyOverdue(e.target.checked)}/>
 Solo vencidas</label>
 <label><input type="checkbox" checked={includeInfo}
 onChange={e=>setIncludeInfo(e.target.checked)}/>
 Incluir informativas</label>
 </div>
 <p>{signals.length} señales; ninguna notificación emitida.</p>
 <ol>{signals.slice(0,limit).map(x=><li key={x.key}
 style={{marginBottom:12}}>
 <button style={button} onClick={()=>setSelected(x.key)}>
 <strong style={{color:levelColor(x.level)}}>{x.level}</strong>{" "}
 {x.code}</button>
 <p>{x.description} · {x.actionId}</p>
 </li>)}</ol>
 {signals.length>limit&&<button style={button}
 onClick={()=>setLimit(x=>x+25)}>Mostrar más</button>}
 {chosen&&<SignalDetail signal={chosen} close={()=>setSelected("")}/>}
 </section>}
 {view==="OWNERS"&&<section style={card}>
 <h3>Carga por responsable</h3>
 {report.workloads.map(x=><OwnerCard key={x.ownerUserId??"NONE"}
 owner={x} onFilter={()=>{setOwner(x.ownerUserId??"NONE");
 setView("SIGNALS");}}/>)}
 {report.workloads.length===0&&<p>Sin acciones registradas;
 esto no implica ausencia de riesgos.</p>}
 </section>}
 {view==="ACTIONS"&&<section style={card}>
 <h3>Historial de trabajo y objetivos</h3>
 <p>{actionRows.length} acciones visibles</p>
 {actionRows.slice(0,limit).map(x=><ActionCard
 key={x.actionId} item={x} onFilter={()=>{
 setSearch(x.actionId);setView("SIGNALS");}}/>)}
 {actionRows.length>limit&&<button style={button}
 onClick={()=>setLimit(x=>x+25)}>Mostrar más</button>}
 </section>}
 {view==="CALENDAR"&&<section style={card}>
 <h3>Contrato horario usado para el cálculo</h3>
 <p>Desplazamiento UTC fijo: {
 report.window.timezoneOffsetMinutes} minutos;
 no incorpora cambios estacionales automáticos.</p>
 <p>Franja: {report.window.openingHour}:00–{
 report.window.closingHour}:00</p>
 <button style={button} onClick={()=>setShowWorkingDays(x=>!x)}>
 {showWorkingDays?"Ocultar":"Mostrar"} días laborables
 </button>
 {showWorkingDays&&<p>Días de la semana (0 domingo):
 {report.window.businessWeekDays.join(", ")}</p>}
 <p>Días excluidos:
 {report.window.exclusions.length?
 report.window.exclusions.join(", "):"Ninguno"}</p>
 <p>Estos plazos sirven para planificación interna y no
 demuestran cumplimiento de SLA contractual con clientes.</p>
 </section>}
 {view==="INTEGRITY"&&<section style={card}>
 <h3>Auditoría y bloqueo de automatizaciones</h3>
 <p>Digest del informe:
 <code style={{overflowWrap:"anywhere"}}>{report.reportDigest}</code></p>
 <p>Incidencias de auditoría: {report.issues.length}</p>
 {report.issues.map(x=><p key={x}>{x}</p>)}
 <p>Fuente truncada: {String(report.overview.sourceTruncated)}</p>
 <p>Correos y mensajes enviados: <strong>0</strong></p>
 <p>Operaciones externas realizadas: <strong>0</strong></p>
 <p>Remediaciones confirmadas: <strong>0</strong></p>
 <p>Un digest SHA-256 no constituye una firma empresarial.</p>
 </section>}
 </>}
 </div>;
}
