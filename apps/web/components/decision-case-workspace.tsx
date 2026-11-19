"use client";
import{useMemo,useState}from "react";
import type{DecisionCaseBoard,DecisionCaseSnapshot,
 DecisionCaseCommand}from "../lib/evidence-decision-case-domain";
import type{EvidenceDecisionReport}from "../lib/evidence-decision-engine";
type Row={
 data:{organizationId:string;board:DecisionCaseBoard;
 correlation:Array<{caseId:string;decisionKey:string;
 decisionStillPresent:boolean;sourceReportChanged:boolean;
 evidenceIdsChanged:boolean;findingIdsChanged:boolean}>;
 currentDecisionReportDigest:string};
 providerCalls:0;remediationVerified:false;
 customerApprovalCreated:false;scoreV1Modified:false;
};
type DecisionEnvelope={report:EvidenceDecisionReport;
 providerCalls:0;customerCertified:false;historicalScoreWrites:0};
type View="BOARD"|"CREATE"|"DETAIL"|"HISTORY"|"QUALITY";
const card:React.CSSProperties={border:"1px solid #94a3b866",
 borderRadius:12,padding:18,marginBottom:16};
const action:React.CSSProperties={border:"1px solid #64748b88",
 background:"transparent",color:"inherit",borderRadius:8,
 padding:"8px 12px",cursor:"pointer"};
const row:React.CSSProperties={display:"flex",alignItems:"center",
 gap:12,flexWrap:"wrap"};
const states=["OPEN","IN_REVIEW","WAITING_EVIDENCE",
 "REVIEW_REPORTED","REOPENED"];
const kinds:Exclude<DecisionCaseCommand,"CREATE">[]=[
 "START","REQUEST_EVIDENCE","REPORT_REVIEW","REOPEN",
 "ASSIGN","EDIT_DUE","LINK_ACTION","COMMENT"];
function Metric({label,value}:{label:string;value:number}){
 return <div style={{...card,minWidth:130,flex:"1 1 130px"}}>
 <small>{label}</small><p style={{fontSize:24,fontWeight:750}}>
 {value}</p></div>;
}
function download(artifact:{filename:string;mime:string;content:string}){
 if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
 throw Error("Nombre de archivo rechazado");
 const url=URL.createObjectURL(new Blob([artifact.content],
 {type:artifact.mime}));
 const a=document.createElement("a");
 a.href=url;a.download=artifact.filename;document.body.append(a);
 a.click();a.remove();URL.revokeObjectURL(url);
}
export function DecisionCaseWorkspace({slug,organizationId,canWrite}:{
 slug:string;organizationId:string;canWrite:boolean;
}){
 const [data,setData]=useState<Row["data"]|null>(null);
 const [decisions,setDecisions]=useState<EvidenceDecisionReport|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState("");
 const [notice,setNotice]=useState(""),[view,setView]=useState<View>("BOARD");
 const [search,setSearch]=useState(""),[status,setStatus]=useState("ALL");
 const [priority,setPriority]=useState("ALL"),[owner,setOwner]=useState("");
 const [unlinkedOnly,setUnlinkedOnly]=useState(false);
 const [overdueOnly,setOverdueOnly]=useState(false);
 const [selected,setSelected]=useState("");
 const [decisionKey,setDecisionKey]=useState("");
 const [newOwner,setNewOwner]=useState(""),[newDue,setNewDue]=useState("");
 const [newNote,setNewNote]=useState("");
 const [relatedAction,setRelatedAction]=useState("");
 const [kind,setKind]=useState<Exclude<DecisionCaseCommand,"CREATE">>("START");
 const [reason,setReason]=useState(""),[modifyOwner,setModifyOwner]=useState("");
 const [modifyDate,setModifyDate]=useState("");
 const [modifyLink,setModifyLink]=useState("");
 const [limit,setLimit]=useState(30);
 const route="/api/organizations/"+encodeURIComponent(slug)+"/decision-cases";
 const source="/api/organizations/"+encodeURIComponent(slug)+
 "/evidence-decisions";
 const refresh=async()=>{
 const res=await fetch(route,{cache:"no-store"});
 const body=await res.json() as Partial<Row>;
 if(!res.ok||body.data?.organizationId!==organizationId||
 body.providerCalls!==0||body.remediationVerified!==false||
 body.customerApprovalCreated!==false||body.scoreV1Modified!==false)
 throw Error("Registro de decisiones incompatible con tenant/contrato");
 setData(body.data);
 };
 const execute=async(task:()=>Promise<void>)=>{
 if(busy)return;
 setBusy(true);setError("");setNotice("");
 try{await task();}
 catch(cause){setError(cause instanceof Error?cause.message:
 "No se pudo completar la acción.");}
 finally{setBusy(false);}
 };
 const load=()=>execute(async()=>{
 await refresh();setNotice("Casos reconciliados con las fuentes persistidas.");
 });
 const loadDecisions=()=>execute(async()=>{
 const res=await fetch(source,{cache:"no-store"});
 const body=await res.json() as Partial<DecisionEnvelope>;
 if(!res.ok||body.report?.organizationId!==organizationId||
 body.providerCalls!==0||body.customerCertified!==false||
 body.historicalScoreWrites!==0)
 throw Error("Decisiones actuales no verificables");
 setDecisions(body.report);setView("CREATE");
 setNotice("Se muestran solo decisiones del tenant actual.");
 });
 const post=async(body:Record<string,unknown>)=>{
 const res=await fetch(route,{method:"POST",cache:"no-store",
 headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
 const parsed=await res.json() as Record<string,unknown>;
 if(!res.ok)throw Error(typeof parsed.code==="string"?
 parsed.code:"Operación rechazada");
 if(parsed.providerCalls!==0||parsed.remediationVerified!==false||
 parsed.customerApprovalCreated!==false||parsed.scoreV1Modified!==false)
 throw Error("Respuesta de seguridad inválida");
 };
 const create=()=>execute(async()=>{
 if(!canWrite)throw Error("No autorizado para gestionar");
 if(!decisions?.decisions.some(x=>x.key===decisionKey&&
 x.code!=="QUARANTINE"))throw Error("Selecciona una decisión válida");
 await post({operation:"CREATE",decisionKey,
 ownerUserId:newOwner.trim()||null,
 dueAt:newDue?new Date(newDue).toISOString():null,
 relatedActionId:relatedAction.trim()||null,
 reviewNote:newNote.trim()||null});
 await refresh();setView("BOARD");
 setDecisionKey("");setNewNote("");
 setNotice("Caso creado; no se ha realizado remediación técnica.");
 });
 const modify=()=>execute(async()=>{
 if(!canWrite)throw Error("No autorizado");
 const item=data?.board.cases.find(x=>x.caseId===selected);
 if(!item)throw Error("Selecciona un caso válido");
 const body:Record<string,unknown>={
 operation:"UPDATE",caseId:item.caseId,
 expectedRevision:item.revision,kind,
 };
 if(["REQUEST_EVIDENCE","REPORT_REVIEW","REOPEN","COMMENT"]
 .includes(kind))body.reason=reason.trim();
 if(kind==="ASSIGN")body.nextOwnerUserId=modifyOwner.trim()||null;
 if(kind==="EDIT_DUE")body.nextDueAt=modifyDate?
 new Date(modifyDate).toISOString():null;
 if(kind==="LINK_ACTION")body.relatedActionId=modifyLink.trim()||null;
 await post(body);await refresh();
 setReason("");setNotice("Transición CAS auditada, sin ejecución externa.");
 });
 const exportFile=(format:"JSON"|"CSV"|"MARKDOWN")=>execute(async()=>{
 const res=await fetch(route+"?format="+format,{cache:"no-store"});
 const body=await res.json();
 if(!res.ok||body.providerCalls!==0||
 body.remediationVerified!==false||body.customerApprovalCreated!==false||
 !body.artifact)throw Error("Exportación denegada");
 download(body.artifact);
 setNotice("Exportado un nuevo corte auditado del tenant.");
 });
 const filtered=useMemo(()=>(data?.board.cases??[]).filter(x=>
 (status==="ALL"||x.status===status)&&
 (priority==="ALL"||x.priority===priority)&&
 (!owner||x.ownerUserId?.includes(owner))&&
 (!unlinkedOnly||x.relatedActionId===null)&&
 (!overdueOnly||x.dueAt!==null&&x.dueAt<data!.board.asOf)&&
 (!search||[x.code,x.domain,x.controlId,x.scope,
 x.decisionKey].join(" ").toLowerCase().includes(search.toLowerCase()))
 ),[data,status,priority,owner,unlinkedOnly,overdueOnly,search]);
 const current=data?.board.cases.find(x=>x.caseId===selected);
 const quality=data?.correlation.find(x=>x.caseId===selected);
 const events=data?.board.events.filter(x=>x.caseId===selected)??[];
 const existingKeys=new Set(data?.board.cases.map(x=>x.decisionKey)??[]);
 const available=(decisions?.decisions??[]).filter(x=>
 !existingKeys.has(x.key)&&x.code!=="QUARANTINE");
 return <div>
 <section style={card}>
 <h2>Casos de revisión de evidencias</h2>
 <p>Cada caso conserva la decisión fuente, IDs de evidencia,
 actor, revisión CAS y acciones relacionadas. Marcar REVIEW_REPORTED
 no equivale a una verificación independiente.</p>
 <div style={row}>
 <button style={action} disabled={busy} onClick={load}>
 Consultar casos</button>
 <button style={action} disabled={busy||!canWrite} onClick={loadDecisions}>
 Crear desde decisión actual</button>
 {(["JSON","CSV","MARKDOWN"] as const).map(x=>
 <button style={action} key={x} disabled={!data||busy}
 onClick={()=>exportFile(x)}>Exportar {x}</button>)}
 </div>
 {busy&&<p role="status">Reconciliando eventos y decisiones…</p>}
 {error&&<p role="alert">{error}</p>}
 {notice&&<p role="status">{notice}</p>}
 </section>
 {data&&<>
 <section style={card}>
 <div style={row}>
 <Metric label="Casos" value={data.board.counts.total}/>
 <Metric label="Abiertos" value={data.board.counts.open}/>
 <Metric label="En revisión" value={data.board.counts.inReview}/>
 <Metric label="Esperando pruebas" value={data.board.counts.waitingEvidence}/>
 <Metric label="Sin responsable" value={data.board.counts.unowned}/>
 <Metric label="Vencidos" value={data.board.counts.overdue}/>
 <Metric label="Auditoría inconsistente" value={data.board.counts.invalidAudit}/>
 </div>
 <p>Estado de fuente actual: {data.currentDecisionCount} decisiones;
 digest <code>{data.currentDecisionReportDigest}</code>.</p>
 <div style={row}>{(["BOARD","CREATE","DETAIL","HISTORY","QUALITY"] as View[]).map(x=><button key={x} style={{...action,
 fontWeight:view===x?750:400}} onClick={()=>setView(x)}>{x}</button>)}</div>
 </section>
 {view==="CREATE"&&<section style={card}>
 <h3>Seguimiento desde una decisión persistida</h3>
 <p>No se admiten IDs de hallazgos inventados.
 La decisión se revalida en servidor antes de persistir.</p>
 <div style={row}>
 <label>Decisión{" "}<select value={decisionKey}
 onChange={e=>setDecisionKey(e.target.value)}>
 <option value="">Selecciona revisión</option>
 {available.map(x=><option key={x.key} value={x.key}>
 {x.priority} · {x.code} · {x.controlId}</option>)}
 </select></label>
 <label>Responsable (ID del miembro){" "}
 <input value={newOwner} onChange={e=>setNewOwner(e.target.value)}/></label>
 <label>Fecha límite{" "}
 <input type="datetime-local" value={newDue}
 onChange={e=>setNewDue(e.target.value)}/></label>
 <label>Acción de riesgo existente (opcional){" "}
 <input value={relatedAction}
 onChange={e=>setRelatedAction(e.target.value)}/></label>
 </div>
 <label>Comentario{" "}
 <textarea rows={3} value={newNote}
 onChange={e=>setNewNote(e.target.value)}/></label>
 <button style={action} disabled={!canWrite||busy||!decisionKey}
 onClick={create}>Crear caso auditado</button>
 </section>}
 {view==="BOARD"&&<section style={card}>
 <h3>Registro de decisiones en seguimiento</h3>
 <div style={row}>
 <label>Buscar{" "}<input value={search}
 onChange={e=>setSearch(e.target.value)}/></label>
 <label>Estado{" "}<select value={status}
 onChange={e=>setStatus(e.target.value)}>
 <option value="ALL">Todos</option>
 {states.map(x=><option value={x} key={x}>{x}</option>)}
 </select></label>
 <label>Prioridad{" "}<select value={priority}
 onChange={e=>setPriority(e.target.value)}>
 <option value="ALL">Todas</option>
 {["P0","P1","P2","P3"].map(x=>
 <option value={x} key={x}>{x}</option>)}
 </select></label>
 <label>Responsable{" "}<input value={owner}
 onChange={e=>setOwner(e.target.value)}/></label>
 <label><input type="checkbox" checked={unlinkedOnly}
 onChange={e=>setUnlinkedOnly(e.target.checked)}/>
 Sin acción relacionada</label>
 <label><input type="checkbox" checked={overdueOnly}
 onChange={e=>setOverdueOnly(e.target.checked)}/>
 Solo vencidos</label>
 </div>
 <p>{filtered.length} casos.</p>
 <ol>{filtered.slice(0,limit).map(x=><li key={x.caseId}>
 <button style={action} onClick={()=>{
 setSelected(x.caseId);setView("DETAIL");}}>
 {x.priority} · {x.code} · {x.controlId}</button>
 <p>{x.status} · responsable {x.ownerUserId??"sin asignar"} ·
 revisión {x.revision}</p>
 </li>)}</ol>
 {filtered.length>limit&&<button style={action}
 onClick={()=>setLimit(x=>x+30)}>Mostrar más</button>}
 </section>}
 {view==="DETAIL"&&<section style={card}>
 <h3>Detalle y transición CAS</h3>
 {!current?<p>Selecciona un caso en el tablero.</p>:<>
 <p>Decisión: <code>{current.decisionKey}</code></p>
 <p>Fuente: <code>{current.sourceReportDigest}</code></p>
 <p>Estado: {current.status} · revisión {current.revision} ·
 responsable: {current.ownerUserId??"no asignado"}</p>
 <p>Control: {current.controlId} · {current.domain} ·
 scope {current.scope}</p>
 <p>Evidencias originales: {current.evidenceIds.length} ·
 hallazgos originales: {current.findingIds.length}</p>
 <p>Acción relacionada: {current.relatedActionId??"Ninguna"}</p>
 <p>Fecha objetivo: {current.dueAt??"Sin fecha"}</p>
 {quality&&<p>Decisión todavía presente:
 {String(quality.decisionStillPresent)} ·
 fuente cambiada: {String(quality.sourceReportChanged)} ·
 evidencia cambiada: {String(quality.evidenceIdsChanged)}</p>}
 <p><strong>Remediación técnica independiente: NO.</strong></p>
 {canWrite&&<>
 <h4>Registrar transición</h4>
 <div style={row}>
 <label>Operación{" "}<select value={kind}
 onChange={e=>setKind(e.target.value as typeof kind)}>
 {kinds.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 {kind==="ASSIGN"&&<label>Responsable{" "}
 <input value={modifyOwner}
 onChange={e=>setModifyOwner(e.target.value)}/></label>}
 {kind==="EDIT_DUE"&&<label>Vencimiento{" "}
 <input type="datetime-local" value={modifyDate}
 onChange={e=>setModifyDate(e.target.value)}/></label>}
 {kind==="LINK_ACTION"&&<label>Acción (ID){" "}
 <input value={modifyLink}
 onChange={e=>setModifyLink(e.target.value)}/></label>}
 </div>
 {["REQUEST_EVIDENCE","REPORT_REVIEW","REOPEN","COMMENT"]
 .includes(kind)&&<label>Motivo{" "}
 <textarea rows={3} maxLength={3000} value={reason}
 onChange={e=>setReason(e.target.value)}/></label>}
 <button style={action} disabled={busy} onClick={modify}>
 Registrar revisión {current.revision+1}</button>
 </>}
 </>}
 </section>}
 {view==="HISTORY"&&<section style={card}>
 <h3>Eventos históricos inmutables</h3>
 <ol>{data.board.events.slice(0,limit).map(e=><li
 key={e.caseId+"-"+e.revision}>
 {e.kind} · {e.previousStatus} → {e.nextStatus} ·
 actor {e.actorUserId} · {e.occurredAt}
 </li>)}</ol>
 </section>}
 {view==="QUALITY"&&<section style={card}>
 <h3>Conciliación con fuente actual</h3>
 {data.correlation.map(x=><p key={x.caseId}>
 <code>{x.caseId}</code> · presente: {String(x.decisionStillPresent)} ·
 digest cambiado: {String(x.sourceReportChanged)} ·
 evidencia cambiada: {String(x.evidenceIdsChanged)}
 </p>)}
 <p>Un caso revisado no sustituye una evaluación técnica ni
 la autorización legal del cliente.</p>
 </section>}
 </>}
 </div>;
}
