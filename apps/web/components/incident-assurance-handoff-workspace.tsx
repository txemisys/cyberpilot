"use client";
import {useCallback,useEffect,useState} from "react";
type Priority="P0"|"P1"|"P2";
type Status="UNASSIGNED"|"ASSIGNED"|"ACCEPTED"|"NEEDS_EVIDENCE"|
  "ESCALATED_INTERNAL"|"REVIEWED_INTERNAL"|"REOPENED";
type Item={
  id:string;controlId:string;category:string;controlState:string;
  importance:string;priority:Priority;suggestedOwnerRole:string;
  guidance:string;dueAt:string;assignedUserId:string|null;
  assignedBy:string|null;acceptedBy:string|null;status:Status;
  revision:number;escalationCount:number;needsEvidence:string[];
  evidenceReferences:string[];notes:Array<{id:string;text:string;
    authorId:string;at:string}>;externalWrites:0;
};
type Board={
  id:string;incidentId:string;revision:number;status:string;
  policyId:string;handoffs:Item[];sourceCoverage:string;
  unknownCount:number;criticalFailures:number;
  providerWrites:0;providerContainmentVerified:false;
};
type Summary={total:number;overdue:number;unassigned:number;
  unresolvedCritical:number;escalated:number;reviewedInternal:number;
  overdueIds:string[]};
type Escalation={handoffId:string;priority:Priority;
  reason:string;state:"PROPOSED_NOT_DISPATCHED";dueAt:string};
type Detail={board:Board;summary:Summary;events:Array<{
  revision:number;kind:string;actorId:string;eventDigest:string;
}>;escalationPlan:{proposals:Escalation[];actualDispatches:0};
  caseRevisionDrift:boolean;providerWrites:0};
type Case={id:string;title:string;status:string;severity:string};
type Action="ASSIGN"|"ACCEPT"|"NEEDS_EVIDENCE"|"ADD_NOTE"|
  "ADD_REFERENCE"|"ESCALATE_INTERNAL"|"ACK_DEADLINE"|
  "COMPLETE_INTERNAL_REVIEW"|"REOPEN"|"CLOSE_BOARD"|"SUPERSEDE_BOARD";
export function IncidentAssuranceHandoffWorkspace({slug,userId,canWrite}:{
  slug:string;userId:string;canWrite:boolean;
}){
  const root="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/assurance-handoffs";
  const casesUrl="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/situation";
  const [cases,setCases]=useState<Case[]>([]);
  const [selected,setSelected]=useState("");
  const [boards,setBoards]=useState<Board[]>([]);
  const [next,setNext]=useState<number|null>(null);
  const [detail,setDetail]=useState<Detail|null>(null);
  const [assignee,setAssignee]=useState("");
  const [reference,setReference]=useState("");
  const [reason,setReason]=useState("");
  const [successor,setSuccessor]=useState("");
  const [priority,setPriority]=useState("ALL");
  const [status,setStatus]=useState("ALL");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [message,setMessage]=useState("");
  const [showEvents,setShowEvents]=useState(false);
  const [showProposals,setShowProposals]=useState(true);
  const board=detail?.board??null;
  const items=board?.handoffs.filter(x=>
    (priority==="ALL"||x.priority===priority)&&
    (status==="ALL"||x.status===status))??[];
  async function call<T>(url:string,method="GET",input?:unknown):Promise<T>{
    const response=await fetch(url,{method,cache:"no-store",
      ...(input===undefined?{}:{headers:{"Content-Type":"application/json"},
        body:JSON.stringify(input)})});
    const parsed=await response.json();
    if(!response.ok)throw Error(parsed.code??"HANDOFF_HTTP_"+response.status);
    return parsed.data as T;
  }
  const loadCases=useCallback(async()=>{
    const data=await call<{cases:Case[]}>(casesUrl+"?mode=index&limit=100");
    setCases(data.cases);
  },[casesUrl]);
  const loadBoards=useCallback(async(incidentId:string,offset=0)=>{
    if(!incidentId){setBoards([]);setNext(null);return;}
    const params=new URLSearchParams({mode:"index",incidentId,
      offset:String(offset),limit:"30"});
    const data=await call<{boards:Board[];nextOffset:number|null}>(
      root+"?"+params);
    setBoards(previous=>offset?[...previous,...data.boards.filter(x=>
      !previous.some(y=>y.id===x.id))]:data.boards);
    setNext(data.nextOffset);
  },[root]);
  const loadDetail=useCallback(async(id:string)=>{
    const data=await call<Detail>(root+"?mode=detail&boardId="+
      encodeURIComponent(id));
    setDetail(data);
  },[root]);
  useEffect(()=>{void loadCases().catch(e=>setError(String(e)));},[loadCases]);
  useEffect(()=>{
    void loadBoards(selected).catch(e=>setError(String(e)));setDetail(null);
  },[selected,loadBoards]);
  async function run(task:()=>Promise<void>){
    setError("");setMessage("");setBusy(true);
    try{await task();}catch(e){setError(String(e));}
    finally{setBusy(false);}
  }
  async function create(){
    if(!selected)return;
    await run(async()=>{
      const data=await call<{board:Board}>(root,"POST",{
        boardId:"board-"+crypto.randomUUID(),
        request:{
          situation:{incidentId:selected,evidence:null,
            assets:null,remediation:null,consistency:"FAIL_CLOSED"},
        },
      });
      await loadBoards(selected);
      await loadDetail(data.board.id);
      setMessage("Tablero interno persistido; fuentes no seleccionadas permanecen UNKNOWN.");
    });
  }
  async function command(action:Action,handoffId?:string){
    if(!board)return;
    await run(async()=>{
      const value=await call<{board:Board}>(root,"PATCH",{
        boardId:board.id,expectedRevision:board.revision,
        commandId:"handoff-command-"+crypto.randomUUID(),
        action:{
          kind:action,reason:reason.trim()||
            "Registro de coordinación interna de la organización",
          ...(handoffId?{handoffId}:{}),
          ...(action==="ASSIGN"?{assigneeId:assignee.trim()}:{}),
          ...(action==="ADD_REFERENCE"?{referenceId:reference.trim()}:{}),
          ...(action==="SUPERSEDE_BOARD"?{successorId:successor.trim()}:{}),
        },
      });
      await loadDetail(value.board.id);
      await loadBoards(selected);
      setReason("");setReference("");
      setMessage("Transición interna confirmada por CAS y registrada en auditoría.");
    });
  }
  function exportBoard(){
    if(!detail)return;
    const blob=new Blob([JSON.stringify({
      schema:"cyberpilot.incident.assurance.handoff.export.v1",
      exportedAt:new Date().toISOString(),board:detail.board,
      summary:detail.summary,events:detail.events,
      escalationProposals:detail.escalationPlan,
      providerWrites:0,externalNotifications:0,
      independentlyVerifiedProviderOutcome:false,
    },null,2)],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const anchor=document.createElement("a");
    anchor.href=url;anchor.download="assurance-handoffs-"+detail.board.id+".json";
    anchor.click();URL.revokeObjectURL(url);
  }
  return <section aria-label="Coordinación de aseguramiento">
    <p role="note">Los controles se convierten en tareas internas con asignación
      verificable, separación de responsabilidades, vencimiento y auditoría.
      Ningún aviso externo se envía automáticamente.</p>
    <h2>Casos en la organización</h2>
    <label>Incidente
      <select disabled={busy} value={selected}
        onChange={e=>setSelected(e.target.value)}>
        <option value="">Seleccione incidente</option>
        {cases.map(x=><option value={x.id} key={x.id}>
          {x.title} · {x.severity} · {x.status}</option>)}
      </select>
    </label>
    {canWrite&&<button disabled={!selected||busy} type="button"
      onClick={()=>void create()}>Crear tablero de seguimiento</button>}
    {error&&<p role="alert">{error}</p>}
    {message&&<p role="status">{message}</p>}
    {selected&&<section>
      <h3>Tableros persistidos</h3>
      {boards.length===0?<p>Sin tableros para el incidente.</p>:
        <ul>{boards.map(x=><li key={x.id}>
          <button type="button" disabled={busy}
            onClick={()=>void run(()=>loadDetail(x.id))}>
            {x.id} — {x.status} — revisión {x.revision}
          </button>
        </li>)}</ul>}
      {next!==null&&<button type="button" disabled={busy}
        onClick={()=>void run(()=>loadBoards(selected,next))}>Cargar más</button>}
    </section>}
    {board&&detail&&<section aria-label="Tablero actual">
      <h2>Aseguramiento interno: {board.status}</h2>
      <dl>
        <dt>Revisión CAS</dt><dd>{board.revision}</dd>
        <dt>Política</dt><dd>{board.policyId}</dd>
        <dt>Controles</dt><dd>{detail.summary.total}</dd>
        <dt>Sin asignar</dt><dd>{detail.summary.unassigned}</dd>
        <dt>Vencidos</dt><dd>{detail.summary.overdue}</dd>
        <dt>Críticos pendientes</dt><dd>{detail.summary.unresolvedCritical}</dd>
        <dt>Escalados internamente</dt><dd>{detail.summary.escalated}</dd>
        <dt>Revisados (no verificados externamente)</dt>
        <dd>{detail.summary.reviewedInternal}</dd>
        <dt>Fuente del caso cambió</dt>
        <dd>{detail.caseRevisionDrift?"Sí, necesita reevaluación":"No detectado"}</dd>
        <dt>Proveedor contenido</dt><dd>No acreditado</dd>
      </dl>
      <button type="button" disabled={busy}
        onClick={()=>void run(()=>loadDetail(board.id))}>Actualizar vencimientos</button>
      <button type="button" onClick={exportBoard}>Exportar expediente JSON</button>
      <h3>Controles en seguimiento</h3>
      <label>Prioridad
        <select value={priority} onChange={e=>setPriority(e.target.value)}>
          {["ALL","P0","P1","P2"].map(x=>
            <option value={x} key={x}>{x}</option>)}
        </select>
      </label>
      <label>Estado
        <select value={status} onChange={e=>setStatus(e.target.value)}>
          {["ALL","UNASSIGNED","ASSIGNED","ACCEPTED",
            "NEEDS_EVIDENCE","ESCALATED_INTERNAL","REVIEWED_INTERNAL",
            "REOPENED"].map(x=><option value={x} key={x}>{x}</option>)}
        </select>
      </label>
      {canWrite&&board.status==="ACTIVE"&&<section>
        <label>Identificador de usuario asignado
          <input value={assignee} onChange={e=>setAssignee(e.target.value)}/>
        </label>
        <label>Referencia interna de evidencia
          <input value={reference} onChange={e=>setReference(e.target.value)}/>
        </label>
        <label>Motivo o nota de auditoría
          <textarea maxLength={2000} value={reason}
            onChange={e=>setReason(e.target.value)}/>
        </label>
      </section>}
      {items.length===0?<p>No hay controles para este filtro.</p>:
        <ul>{items.map(x=><li key={x.id}>
          <article>
            <h4>{x.priority} · {x.controlId} — {x.status}</h4>
            <p>{x.category} · estado de fuente: {x.controlState}</p>
            <p>{x.guidance}</p>
            <p>Responsable sugerido: {x.suggestedOwnerRole}.</p>
            <p>Asignación: {x.assignedUserId??"pendiente"}.
              Fecha límite: {new Date(x.dueAt).toLocaleString()}.</p>
            <p>Escalados internos: {x.escalationCount}.</p>
            {x.needsEvidence.length>0&&<p>Pruebas requeridas:
              {x.needsEvidence.join("; ")}.</p>}
            {x.evidenceReferences.length>0&&<p>Referencias:
              {x.evidenceReferences.join(", ")}.</p>}
            {x.notes.length>0&&<ul>{x.notes.map(n=>
              <li key={n.id}>{n.authorId}: {n.text}</li>)}</ul>}
            {canWrite&&board.status==="ACTIVE"&&<div>
              {["UNASSIGNED","REOPENED","ASSIGNED"].includes(x.status)&&
                <button type="button" disabled={busy||!assignee}
                  onClick={()=>void command("ASSIGN",x.id)}>Asignar</button>}
              {x.status==="ASSIGNED"&&x.assignedUserId===userId&&
                <button type="button" disabled={busy}
                  onClick={()=>void command("ACCEPT",x.id)}>Aceptar encargo</button>}
              {x.assignedUserId===userId&&
                ["ACCEPTED","NEEDS_EVIDENCE","ESCALATED_INTERNAL"].includes(x.status)&&
                <>
                  <button type="button" disabled={busy}
                    onClick={()=>void command("NEEDS_EVIDENCE",x.id)}>
                    Solicitar pruebas
                  </button>
                  <button type="button" disabled={busy}
                    onClick={()=>void command("COMPLETE_INTERNAL_REVIEW",x.id)}>
                    Finalizar revisión interna
                  </button>
                  <button type="button" disabled={busy||!reference}
                    onClick={()=>void command("ADD_REFERENCE",x.id)}>
                    Añadir referencia
                  </button>
                </>}
              {(x.assignedUserId===userId||x.assignedUserId===null)&&
                <button type="button" disabled={busy}
                  onClick={()=>void command("ESCALATE_INTERNAL",x.id)}>
                  Escalar internamente
                </button>}
              {x.assignedUserId===userId&&
                <button type="button" disabled={busy}
                  onClick={()=>void command("ACK_DEADLINE",x.id)}>
                  Reconocer vencimiento
                </button>}
              {(x.assignedUserId===userId||x.status==="UNASSIGNED")&&
                <button type="button" disabled={busy}
                  onClick={()=>void command("ADD_NOTE",x.id)}>
                  Añadir nota
                </button>}
              {x.status==="REVIEWED_INTERNAL"&&
                <button type="button" disabled={busy}
                  onClick={()=>void command("REOPEN",x.id)}>
                  Reabrir revisión
                </button>}
            </div>}
          </article>
        </li>)}</ul>}
      <h3>Propuestas de escalado (sin envío)</h3>
      <button type="button" onClick={()=>setShowProposals(x=>!x)}>
        {showProposals?"Ocultar":"Mostrar"} propuestas
      </button>
      {showProposals&&<ul>{detail.escalationPlan.proposals.map(x=>
        <li key={x.handoffId}>{x.priority} · {x.handoffId}:
          {x.reason} — {x.state}</li>)}</ul>}
      {canWrite&&board.status==="ACTIVE"&&<section>
        <h3>Cierre de coordinación</h3>
        <button type="button" disabled={busy}
          onClick={()=>void command("CLOSE_BOARD")}>
          Cerrar tablero (solo revisión interna íntegra)</button>
        <label>Tablero sucesor
          <input value={successor} onChange={e=>setSuccessor(e.target.value)}/>
        </label>
        <button type="button" disabled={busy||!successor}
          onClick={()=>void command("SUPERSEDE_BOARD")}>
          Vincular sustitución</button>
      </section>}
      <h3>Eventos auditados</h3>
      <button type="button" onClick={()=>setShowEvents(x=>!x)}>
        {showEvents?"Ocultar":"Mostrar"} cadena ({detail.events.length})
      </button>
      {showEvents&&<ol>{detail.events.map(e=>
        <li key={e.revision}>{e.revision} · {e.kind} · {e.actorId}
          <code>{e.eventDigest}</code>
        </li>)}</ol>}
    </section>}
  </section>;
}
