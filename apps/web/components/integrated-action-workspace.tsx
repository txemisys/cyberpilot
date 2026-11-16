"use client";
import {useMemo,useState} from "react";
import type {
  ActionSnapshot,ActionState,ActionPriority,ActionCommandName,
  ActionBoardSummary,
} from "../lib/integrated-action-domain";
import type {IntegratedRiskDigest} from "../lib/integrated-risk-engine";
type Audit={actionId:string;valid:boolean;errors:string[];
  eventsChecked:number;
  latestStatus:ActionState|null;latestRevision:number};
type ActionRead={
  organizationId:string;asOf:string;actions:ActionSnapshot[];
  history:Array<{actionId:string;revision:number;kind:string;
    previousStatus:string;nextStatus:string;actorUserId:string;
    occurredAt:string}>;
  audits:Audit[];issues:string[];summary:ActionBoardSummary;
  counts:{actions:number;events:number};
  truncated:boolean;externalProviderOperations:0;
  liveRemediationPerformed:false;
  riskAcceptedByClient:false;CyberScoreV1Changed:false;
};
type Envelope={
  data:ActionRead;providerWrites:0;verifiedRemediation:false;
  customerRiskAcceptance:false;legacyCyberScoreChanged:false;
};
type RiskResponse={report:IntegratedRiskDigest;liveProviderCalls:0;
  legacyScoreWrites:0;customerApprovalSigned:false};
type View="BOARD"|"CREATE"|"HISTORY"|"OVERDUE"|"EXCEPTIONS"|"AUDIT";
const views:Array<{key:View;label:string}>=[
  {key:"BOARD",label:"Seguimiento"},
  {key:"CREATE",label:"Añadir desde riesgo"},
  {key:"HISTORY",label:"Auditoría"},
  {key:"OVERDUE",label:"Vencimientos"},
  {key:"EXCEPTIONS",label:"Excepciones"},
  {key:"AUDIT",label:"Integridad"},
];
const states:ActionState[]=[
  "OPEN","IN_PROGRESS","BLOCKED","DONE_REPORTED",
  "EXCEPTION","REOPENED",
];
const priorities:ActionPriority[]=["LOW","NORMAL","HIGH","URGENT"];
const commands:ActionCommandName[]=[
  "ASSIGN","PRIORITIZE","START","BLOCK","REPORT_DONE",
  "ACCEPT_EXCEPTION","REOPEN","EDIT_DUE","COMMENT","EXPIRE_EXCEPTION",
];
const card:React.CSSProperties={
  border:"1px solid #94a3b866",borderRadius:12,
  padding:18,marginBottom:16,
};
const button:React.CSSProperties={
  border:"1px solid #64748b88",background:"transparent",
  color:"inherit",padding:"8px 12px",borderRadius:8,cursor:"pointer",
};
const row:React.CSSProperties={
  display:"flex",gap:12,flexWrap:"wrap",alignItems:"center",
};
function guard(body:unknown,tenant:string):body is Envelope{
  if(!body||typeof body!=="object"||Array.isArray(body))return false;
  const data=body as Partial<Envelope>;
  return data.providerWrites===0&&
    data.verifiedRemediation===false&&
    data.customerRiskAcceptance===false&&
    data.legacyCyberScoreChanged===false&&
    data.data?.organizationId===tenant&&
    Array.isArray(data.data.actions)&&
    data.data.liveRemediationPerformed===false&&
    data.data.CyberScoreV1Changed===false;
}
function statusColor(state:ActionState){
  if(state==="BLOCKED")return"#b91c1c";
  if(state==="DONE_REPORTED")return"#0f766e";
  if(state==="EXCEPTION")return"#a16207";
  return"#475569";
}
function Metric({title,value}:{
  title:string;value:number|string;
}){
  return <div style={{...card,minWidth:130,flex:"1 1 130px"}}>
    <small>{title}</small>
    <p style={{fontSize:24,fontWeight:750,margin:"6px 0"}}>{value}</p>
  </div>;
}
export function IntegratedActionWorkspace({
  slug,organizationId,canWrite,
}:{slug:string;organizationId:string;canWrite:boolean}){
  const [data,setData]=useState<ActionRead|null>(null);
  const [riskReport,setRiskReport]=useState<IntegratedRiskDigest|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [tab,setTab]=useState<View>("BOARD");
  const [query,setQuery]=useState("");
  const [status,setStatus]=useState<ActionState|"ALL">("ALL");
  const [priority,setPriority]=useState<ActionPriority|"ALL">("ALL");
  const [owner,setOwner]=useState("");
  const [order,setOrder]=useState<"PRIORITY"|"DUE"|"UPDATED">("PRIORITY");
  const [selected,setSelected]=useState("");
  const [riskKey,setRiskKey]=useState("");
  const [newPriority,setNewPriority]=useState<ActionPriority>("NORMAL");
  const [newOwner,setNewOwner]=useState("");
  const [newDue,setNewDue]=useState("");
  const [newRationale,setNewRationale]=useState("");
  const [kind,setKind]=useState<ActionCommandName>("START");
  const [commandReason,setCommandReason]=useState("");
  const [commandOwner,setCommandOwner]=useState("");
  const [commandDue,setCommandDue]=useState("");
  const [commandPriority,setCommandPriority]=useState<ActionPriority>("NORMAL");
  const [exceptionEnd,setExceptionEnd]=useState("");
  const [showHistory,setShowHistory]=useState(false);
  const [limit,setLimit]=useState(30);
  const route="/api/organizations/"+encodeURIComponent(slug)+
    "/integrated-actions";
  const riskRoute="/api/organizations/"+encodeURIComponent(slug)+
    "/integrated-risks";
  const execute=async(action:()=>Promise<void>)=>{
    if(busy)return;
    setBusy(true);setError("");setNotice("");
    try{await action();}
    catch(cause){
      setError(cause instanceof Error?cause.message:"Operación rechazada.");
    }finally{setBusy(false);}
  };
  const fetchData=async()=>{
    const response=await fetch(route,{cache:"no-store"});
    const content:unknown=await response.json();
    if(!response.ok||!guard(content,organizationId))
      throw Error("No se pudo verificar el tablero de acciones.");
    setData(content.data);
    setSelected("");
  };
  const load=()=>execute(async()=>{
    await fetchData();
    setNotice("Registro de seguimiento actualizado desde PostgreSQL.");
  });
  const loadRisks=()=>execute(async()=>{
    const response=await fetch(riskRoute,{cache:"no-store"});
    const body=await response.json() as Partial<RiskResponse>;
    if(!response.ok||body.report?.organizationId!==organizationId||
      body.liveProviderCalls!==0||body.legacyScoreWrites!==0||
      body.customerApprovalSigned!==false)
      throw Error("Riesgos sin origen verificable.");
    setRiskReport(body.report);
    setTab("CREATE");
    setNotice("Riesgos abiertos listados desde registros persistidos.");
  });
  const post=async(command:Record<string,unknown>)=>{
    const response=await fetch(route,{
      method:"POST",cache:"no-store",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify(command),
    });
    const value=await response.json() as Record<string,unknown>;
    if(!response.ok)
      throw Error(typeof value.code==="string"?
        value.code:"No se pudo registrar el cambio.");
    if(value.providerWrites!==0||value.verifiedRemediation!==false||
      value.customerRiskAcceptance!==false||
      value.legacyCyberScoreChanged!==false)
      throw Error("El servidor declaró operaciones no permitidas.");
  };
  const create=()=>execute(async()=>{
    if(!canWrite)throw Error("No autorizado para modificar.");
    if(!riskReport||!riskReport.risks.some(x=>
      x.key===riskKey&&x.status==="OPEN"))
      throw Error("Selecciona un riesgo abierto persistido.");
    await post({
      operation:"CREATE",riskKey,priority:newPriority,
      ownerUserId:newOwner.trim()||null,
      dueAt:newDue?new Date(newDue).toISOString():null,
      rationale:newRationale.trim()||null,
    });
    await fetchData();
    setTab("BOARD");setRiskKey("");setNewRationale("");
    setNotice("Acción persistida. Ningún control ha sido remediado.");
  });
  const modify=()=>execute(async()=>{
    if(!canWrite)throw Error("No autorizado para modificar.");
    const selectedAction=data?.actions.find(x=>x.actionId===selected);
    if(!selectedAction)throw Error("Selecciona una acción.");
    const input:Record<string,unknown>={
      operation:"UPDATE",actionId:selectedAction.actionId,
      expectedRevision:selectedAction.revision,kind,
    };
    if(kind==="ASSIGN")
      input.nextOwnerUserId=commandOwner.trim()||null;
    if(kind==="PRIORITIZE")
      input.nextPriority=commandPriority;
    if(kind==="EDIT_DUE")
      input.nextDueAt=commandDue?
        new Date(commandDue).toISOString():null;
    if(["BLOCK","REPORT_DONE","ACCEPT_EXCEPTION","COMMENT",
      "REOPEN"].includes(kind))
      input.reason=commandReason.trim();
    if(kind==="ACCEPT_EXCEPTION")
      input.exceptionExpiresAt=exceptionEnd?
        new Date(exceptionEnd).toISOString():null;
    await post(input);
    await fetchData();
    setCommandReason("");
    setNotice("Cambio registrado con auditoría y CAS. Sin remediación LIVE.");
  });
  const filtered=useMemo(()=>{
    const needle=query.trim().toLowerCase();
    const list=(data?.actions??[]).filter(x=>
      (status==="ALL"||x.status===status)&&
      (priority==="ALL"||x.priority===priority)&&
      (!owner||x.ownerUserId?.includes(owner))&&
      (!needle||[x.title,x.description,x.riskKey,x.severity,
        x.ownerUserId??"",x.rationale??""]
        .join(" ").toLowerCase().includes(needle)));
    return [...list].sort((a,b)=>{
      if(order==="UPDATED")return b.updatedAt.localeCompare(a.updatedAt);
      if(order==="DUE")
        return (a.dueAt??"9999").localeCompare(b.dueAt??"9999");
      const ranks={URGENT:0,HIGH:1,NORMAL:2,LOW:3};
      return ranks[a.priority]-ranks[b.priority]||
        (a.dueAt??"9999").localeCompare(b.dueAt??"9999");
    });
  },[data,query,status,priority,owner,order]);
  const active=data?.actions.find(x=>x.actionId===selected);
  const items=data?.history.filter(x=>x.actionId===selected)??[];
  const audit=data?.audits.find(x=>x.actionId===selected);
  const risks=riskReport?.risks.filter(x=>x.status==="OPEN")??[];
  const taken=new Set(data?.actions.map(x=>x.riskKey)??[]);
  const available=risks.filter(x=>!taken.has(x.key));
  return <div>
    <section style={card}>
      <h2>Plan de acción sin conectores</h2>
      <p>Asignación y seguimiento humano de riesgos persistidos,
        con revisión optimista, excepciones con vencimiento y
        procedencia inmutable. DONE_REPORTED nunca significa
        remediación técnica comprobada.</p>
      <div style={row}>
        <button style={button} disabled={busy} onClick={load}>
          Consultar acciones
        </button>
        <button style={button} disabled={busy||!canWrite}
          onClick={loadRisks}>Añadir riesgo existente</button>
      </div>
      {busy&&<p role="status">Actualizando seguimiento tenant-scoped…</p>}
      {error&&<p role="alert">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
    </section>
    {data&&<>
      <section style={row}>
        <Metric title="Abiertas" value={data.summary.open}/>
        <Metric title="En curso" value={data.summary.inProgress}/>
        <Metric title="Bloqueadas" value={data.summary.blocked}/>
        <Metric title="Vencidas" value={data.summary.overdue}/>
        <Metric title="Completadas declaradas"
          value={data.summary.doneReported}/>
        <Metric title="Excepciones" value={data.summary.exceptions}/>
      </section>
      <section style={card}>
        <div style={row}>{views.map(x=><button key={x.key}
          style={{...button,fontWeight:tab===x.key?750:400}}
          onClick={()=>setTab(x.key)}>{x.label}</button>)}</div>
        <p>Evaluado: {data.asOf} · Registro:
          {data.counts.actions} acciones, {data.counts.events} eventos.</p>
        {data.truncated&&<p role="alert">
          Se alcanzó el límite de lectura; la auditoría es incompleta.</p>}
      </section>
      {tab==="CREATE"&&<section style={card}>
        <h3>Crear seguimiento desde un riesgo existente</h3>
        <p>No se admiten hallazgos creados libremente desde esta pantalla:
          deben existir en el registro integrado del tenant.</p>
        <button style={button} onClick={loadRisks}
          disabled={busy}>Recargar riesgos elegibles</button>
        <div style={row}>
          <label>Riesgo{" "}
            <select value={riskKey}
              onChange={e=>setRiskKey(e.target.value)}>
              <option value="">Selecciona riesgo</option>
              {available.map(x=><option key={x.key} value={x.key}>
                {x.severity} · {x.title}
              </option>)}
            </select>
          </label>
          <label>Prioridad{" "}
            <select value={newPriority}
              onChange={e=>setNewPriority(
                e.target.value as ActionPriority)}>
              {priorities.map(x=><option key={x} value={x}>{x}</option>)}
            </select>
          </label>
          <label>ID de responsable{" "}
            <input value={newOwner}
              onChange={e=>setNewOwner(e.target.value)}
              placeholder="ID de miembro (opcional)"/>
          </label>
          <label>Vencimiento{" "}
            <input type="datetime-local" value={newDue}
              onChange={e=>setNewDue(e.target.value)}/>
          </label>
        </div>
        <label>Justificación{" "}
          <textarea rows={3} value={newRationale}
            onChange={e=>setNewRationale(e.target.value)}/>
        </label>
        <p>El responsable se verifica en PostgreSQL y debe pertenecer
          a la misma organización.</p>
        <button style={button} disabled={!riskKey||busy||!canWrite}
          onClick={create}>Crear seguimiento auditado</button>
      </section>}
      {(tab==="BOARD"||tab==="OVERDUE"||tab==="EXCEPTIONS")&&
        <section style={card}>
          <h3>Acciones y estados</h3>
          <div style={row}>
            <label>Buscar{" "}
              <input value={query}
                onChange={e=>{setQuery(e.target.value);setLimit(30);}}/>
            </label>
            <label>Estado{" "}
              <select value={status}
                onChange={e=>setStatus(e.target.value as typeof status)}>
                <option value="ALL">Todos</option>
                {states.map(x=><option key={x} value={x}>{x}</option>)}
              </select>
            </label>
            <label>Prioridad{" "}
              <select value={priority}
                onChange={e=>setPriority(
                  e.target.value as typeof priority)}>
                <option value="ALL">Todas</option>
                {priorities.map(x=><option key={x} value={x}>{x}</option>)}
              </select>
            </label>
            <label>Responsable{" "}
              <input value={owner} onChange={e=>setOwner(e.target.value)}
                placeholder="ID"/>
            </label>
            <label>Orden{" "}
              <select value={order}
                onChange={e=>setOrder(e.target.value as typeof order)}>
                <option value="PRIORITY">Prioridad</option>
                <option value="DUE">Vencimiento</option>
                <option value="UPDATED">Más reciente</option>
              </select>
            </label>
          </div>
          <ul>{filtered.filter(x=>tab==="OVERDUE"?
            Boolean(x.dueAt&&x.dueAt<data.asOf&&
              !["DONE_REPORTED","EXCEPTION"].includes(x.status)):
            tab==="EXCEPTIONS"?x.status==="EXCEPTION":true)
            .slice(0,limit).map(x=><li key={x.actionId}
              style={{marginBottom:14}}>
              <button style={button} onClick={()=>{
                setSelected(x.actionId);setKind("START");
                setCommandPriority(x.priority);
                setCommandOwner(x.ownerUserId??"");
              }}>{x.title}</button>{" "}
              <strong style={{color:statusColor(x.status)}}>{x.status}</strong>
              <p>{x.priority} · {x.severity} ·
                revisión {x.revision} · responsable:
                {x.ownerUserId??"sin asignar"}</p>
              <p>Fecha objetivo: {x.dueAt??"sin fecha"} ·
                última actualización: {x.updatedAt}</p>
            </li>)}</ul>
          {filtered.length>limit&&<button style={button}
            onClick={()=>setLimit(v=>v+30)}>Mostrar más</button>}
        </section>}
      {active&&tab==="BOARD"&&<section style={card}>
        <div style={row}><h3>{active.title}</h3>
          <button style={button} onClick={()=>setSelected("")}>
            Cerrar detalle
          </button>
        </div>
        <p>Estado {active.status} · versión {active.revision}</p>
        <p>{active.description}</p>
        <p>Risk key: <code>{active.riskKey}</code></p>
        <p>Origen SHA-256: <code>{active.sourceFingerprint}</code></p>
        <p>Seguimiento: {active.rationale??"sin comentarios"}</p>
        <p>Evidencias referenciadas:
          {active.evidenceRefs.length} (solo identificadores)</p>
        {active.exceptionReason&&<p>
          Excepción declarada: {active.exceptionReason} · vence
          {active.exceptionExpiresAt}
        </p>}
        <p><strong>Remediación independiente verificada: NO.</strong></p>
        {canWrite&&<>
          <h4>Transición con control de revisión CAS</h4>
          <div style={row}>
            <label>Operación{" "}
              <select value={kind}
                onChange={e=>setKind(e.target.value as ActionCommandName)}>
                {commands.map(x=><option key={x} value={x}>{x}</option>)}
              </select>
            </label>
            {kind==="ASSIGN"&&<label>Responsable (ID){" "}
              <input value={commandOwner}
                onChange={e=>setCommandOwner(e.target.value)}/>
            </label>}
            {kind==="PRIORITIZE"&&<label>Prioridad{" "}
              <select value={commandPriority}
                onChange={e=>setCommandPriority(
                  e.target.value as ActionPriority)}>
                {priorities.map(x=><option key={x} value={x}>{x}</option>)}
              </select>
            </label>}
            {kind==="EDIT_DUE"&&<label>Fecha límite{" "}
              <input type="datetime-local" value={commandDue}
                onChange={e=>setCommandDue(e.target.value)}/>
            </label>}
            {kind==="ACCEPT_EXCEPTION"&&<label>Caducidad{" "}
              <input type="datetime-local" value={exceptionEnd}
                onChange={e=>setExceptionEnd(e.target.value)}/>
            </label>}
          </div>
          {["BLOCK","REPORT_DONE","ACCEPT_EXCEPTION","COMMENT",
            "REOPEN"].includes(kind)&&<label>Motivo{" "}
            <textarea rows={3} maxLength={2000} value={commandReason}
              onChange={e=>setCommandReason(e.target.value)}/>
          </label>}
          <button style={button} disabled={busy} onClick={modify}>
            Registrar transición v{active.revision} → v{active.revision+1}
          </button>
          <p>Las modificaciones simultáneas se rechazan, no
            sobrescriben silenciosamente el trabajo de otro miembro.</p>
        </>}
        <button style={button}
          onClick={()=>setShowHistory(x=>!x)}>
          {showHistory?"Ocultar":"Mostrar"} auditoría de acción
        </button>
        {showHistory&&<ol>{items.map((event,i)=>
          <li key={event.revision+"-"+i}>
            {event.kind} · {event.previousStatus} →
            {event.nextStatus} · {event.occurredAt}
          </li>)}</ol>}
        {audit&&!audit.valid&&<p role="alert">
          La cadena de eventos no concuerda con el registro persistido:
          {audit.errors.join(", ")}
        </p>}
      </section>}
      {tab==="HISTORY"&&<section style={card}>
        <h3>Eventos inmutables</h3>
        <p>Este listado muestra cambios declarados por personas.
          No equivale a una acción ejecutada contra un sistema.</p>
        <ol>{data.history.slice(0,limit).map((event,i)=>
          <li key={event.actionId+"-"+event.revision+"-"+i}>
            <code>{event.actionId}</code> · {event.kind} ·
            revisión {event.revision} · {event.occurredAt} ·
            {event.actorUserId}
          </li>)}</ol>
        {data.history.length>limit&&<button style={button}
          onClick={()=>setLimit(v=>v+30)}>Mostrar más</button>}
      </section>}
      {tab==="AUDIT"&&<section style={card}>
        <h3>Consistencia de fuente y auditoría</h3>
        {data.issues.length?<ul>{data.issues.map(issue=>
          <li key={issue}>{issue}</li>)}</ul>:
          <p>No hay incidencias adicionales entre registros consultados.</p>}
        <ul>{data.audits.map(a=><li key={a.actionId}>
          <strong>{a.valid?"PASS":"BLOCK"}</strong> ·
          <code>{a.actionId}</code> · eventos {a.eventsChecked} ·
          {a.errors.join(", ")||"sin inconsistencias detectadas"}
        </li>)}</ul>
        <p>La ausencia de inconsistencias técnicas no sustituye
          la verificación de remediación ni aceptación legal.</p>
      </section>}
    </>}
  </div>;
}
