"use client";
import { useCallback, useEffect, useState } from "react";
type Type="COMPROMISED_ACCOUNT"|"PHISHING_CAMPAIGN"|"RANSOMWARE"|
  "LOST_DEVICE"|"PAYMENT_FRAUD";
type Role="INCIDENT_COMMANDER"|"SECURITY_REVIEWER"|"IT_OPERATOR"|
  "FINANCE_APPROVER"|"LEGAL_REVIEWER"|"EVIDENCE_COLLECTOR";
type Decision="DECLARE_UNKNOWN"|"COLLECT_EVIDENCE"|"ESCALATE"|
  "REQUEST_INDEPENDENT_APPROVAL"|"MARK_PROVEN"|
  "SEND_PROVIDER_COMMAND"|"SKIP_STEP"|"REQUEST_MANUAL_VERIFICATION";
type Item={id:string;type:Type;title:string;state:string;revision:number;
  participants:number;trainingMoves:number;unsafeAttempts:number;
  updatedAt:string;providerWrites:0};
type Participant={userId:string;role:Role;active:boolean;
  permissions:"FACILITATOR"|"PARTICIPANT"|"OBSERVER"};
type Scenario={id:string;incidentType:Type;scenarioSeed:number;
  injectedFaults:string[];scriptedSignals:Array<{source:string;
    state:string;message:string}>;activeStepIds:string[]};
type Receipt={move:{id:string;stepId:string;command:Decision;
  reason:string;actorRole:Role};userId:string;accepted:boolean;code:string};
type Session={id:string;revision:number;state:string;
  scenario:Scenario;facilitatorId:string;participants:Participant[];
  moveReceipts:Receipt[];notes:Array<{id:string;text:string;userId:string}>;
  debrief:{unsafeAttempts:number;acceptedMoves:number;failedMoves:number;
    unreviewedSteps:string[]}|null;incidentId:string|null;
  externallyExecutedCommands:0;providerContainmentProven:false};
type Detail={session:Session;replay:{identical:boolean;
  divergentMoveIds:string[];liveContainmentProven:false};
  events:Array<{revision:number;kind:string;actorId:string;
    eventDigest:string}>;participant:Participant|null};
const TYPES:Type[]=["COMPROMISED_ACCOUNT","PHISHING_CAMPAIGN",
  "RANSOMWARE","LOST_DEVICE","PAYMENT_FRAUD"];
const ROLES:Role[]=["INCIDENT_COMMANDER","SECURITY_REVIEWER",
  "IT_OPERATOR","FINANCE_APPROVER","LEGAL_REVIEWER","EVIDENCE_COLLECTOR"];
const DECISIONS:Decision[]=["DECLARE_UNKNOWN","COLLECT_EVIDENCE",
  "ESCALATE","REQUEST_INDEPENDENT_APPROVAL","REQUEST_MANUAL_VERIFICATION",
  "MARK_PROVEN","SEND_PROVIDER_COMMAND","SKIP_STEP"];
export function IncidentTabletopSessionWorkspace({slug,userId,canWrite}:{
  slug:string;userId:string;canWrite:boolean;
}){
  const base="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/tabletop-sessions";
  const [items,setItems]=useState<Item[]>([]);
  const [next,setNext]=useState<number|null>(null);
  const [detail,setDetail]=useState<Detail|null>(null);
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const [error,setError]=useState("");
  const [type,setType]=useState<Type>("COMPROMISED_ACCOUNT");
  const [title,setTitle]=useState("Ejercicio de respuesta al incidente");
  const [seed,setSeed]=useState("42");
  const [faultCount,setFaultCount]=useState("5");
  const [step,setStep]=useState("");
  const [decision,setDecision]=useState<Decision>("DECLARE_UNKNOWN");
  const [reason,setReason]=useState("");
  const [person,setPerson]=useState("");
  const [role,setRole]=useState<Role>("SECURITY_REVIEWER");
  const [permissions,setPermissions]=useState<Participant["permissions"]>("PARTICIPANT");
  const [note,setNote]=useState("");
  const [showAudit,setShowAudit]=useState(false);
  const [showAll,setShowAll]=useState(false);
  const session=detail?.session??null;
  const participant=detail?.participant??null;
  const facilitator=session?.facilitatorId===userId&&
    participant?.permissions==="FACILITATOR";
  const active=participant?.active&&participant.permissions!=="OBSERVER";
  async function call<T>(url:string,method="GET",body?:unknown):Promise<T>{
    const r=await fetch(url,{method,cache:"no-store",
      ...(body===undefined?{}:{headers:{"Content-Type":"application/json"},
        body:JSON.stringify(body)})});
    const v=await r.json();
    if(!r.ok)throw Error(v.code??"SESSION_HTTP_"+r.status);
    return v.data as T;
  }
  const index=useCallback(async(offset=0)=>{
    const data=await call<{sessions:Item[];nextOffset:number|null}>(
      base+"?mode=index&offset="+offset+"&limit=30");
    setItems(old=>offset?[...old,...data.sessions.filter(x=>
      !old.some(y=>y.id===x.id))]:data.sessions);
    setNext(data.nextOffset);
  },[base]);
  const load=useCallback(async(id:string)=>{
    const data=await call<Detail>(base+"?mode=detail&sessionId="+
      encodeURIComponent(id));
    setDetail(data);setStep(data.session.scenario.activeStepIds[0]??"");
  },[base]);
  useEffect(()=>{void index().catch(e=>setError(String(e)));},[index]);
  async function run(task:()=>Promise<void>){
    setBusy(true);setError("");setMessage("");
    try{await task();}catch(e){setError(String(e));}
    finally{setBusy(false);}
  }
  async function create(){
    await run(async()=>{
      const id="session-"+crypto.randomUUID();
      const v=await call<{session:Session}>(base,"POST",{
        id,incidentId:null,type,title,seed:Number(seed),
        faultCount:Number(faultCount),additionalFaults:[],
      });
      await index();
      await load(v.session.id);
      setMessage("Sesión de formación persistida: ningún permiso de proveedor utilizado.");
    });
  }
  async function mutate(action:Record<string,unknown>){
    if(!session)return;
    await run(async()=>{
      const value=await call<{session:Session}>(base,"PATCH",{
        sessionId:session.id,commandId:"command-"+crypto.randomUUID(),
        expectedRevision:session.revision,
        action:{...action,userId},
      });
      await load(value.session.id);await index();
      setNote("");setReason("");
      setMessage("Transición CAS persistida. El replay se verifica al releer la sesión.");
    });
  }
  function download(){
    if(!detail)return;
    const content=JSON.stringify({
      schema:"cyberpilot.incident.tabletop.session.dossier.v1",
      exportedAt:new Date().toISOString(),session:detail.session,
      events:detail.events,replay:detail.replay,
      externalProviderWrites:0,actualContainmentVerified:false,
    },null,2);
    const url=URL.createObjectURL(new Blob([content],
      {type:"application/json"}));
    const link=document.createElement("a");link.href=url;
    link.download="tabletop-session-"+detail.session.id+".json";
    link.click();URL.revokeObjectURL(url);
  }
  return <section aria-label="Sesiones tabletop persistentes">
    <p role="note">Ejercicio determinista de los cinco playbooks. Los
      comandos peligrosos se rechazan incluso en la simulación.
      El resultado no prueba mejoras reales en sistemas externos.</p>
    <h2>Sesiones históricas</h2>
    {items.length===0?<p>No se han registrado sesiones.</p>:
      <ul>{items.map(x=><li key={x.id}>
        <button type="button" disabled={busy}
          onClick={()=>void run(()=>load(x.id))}>
          {x.title} · {x.type} · {x.state} · r{x.revision}
        </button>
        <span> {x.trainingMoves} decisiones · {x.unsafeAttempts} intentos inseguros</span>
      </li>)}</ul>}
    {next!==null&&<button type="button" disabled={busy}
      onClick={()=>void run(()=>index(next))}>Cargar más sesiones</button>}
    {canWrite&&<section>
      <h2>Iniciar sesión</h2>
      <label>Playbook
        <select value={type} disabled={busy}
          onChange={e=>setType(e.target.value as Type)}>
          {TYPES.map(x=><option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      <label>Título
        <input maxLength={180} value={title}
          onChange={e=>setTitle(e.target.value)}/>
      </label>
      <label>Semilla determinista
        <input inputMode="numeric" value={seed}
          onChange={e=>setSeed(e.target.value)}/>
      </label>
      <label>Fallos inyectados
        <select value={faultCount} onChange={e=>setFaultCount(e.target.value)}>
          {["1","2","3","4","5","6","7","8"].map(x=>
            <option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      <button type="button" disabled={busy||title.trim().length<5}
        onClick={()=>void create()}>Persistir nueva sesión</button>
    </section>}
    {message&&<p role="status">{message}</p>}
    {error&&<p role="alert">{error}</p>}
    {session&&detail&&<section aria-label="Detalles del tabletop">
      <h2>{session.scenario.incidentType} · {session.state}</h2>
      <dl>
        <dt>Revisión CAS</dt><dd>{session.revision}</dd>
        <dt>Semilla reproducible</dt><dd>{session.scenario.scenarioSeed}</dd>
        <dt>Facilitador</dt><dd>{session.facilitatorId}</dd>
        <dt>Participación actual</dt>
        <dd>{participant?participant.role+" / "+participant.permissions:
          "Sin participante activo asignado"}</dd>
        <dt>Replay íntegro</dt>
        <dd>{detail.replay.identical?"Verificado en almacenamiento":"Divergente"}</dd>
        <dt>Contención real verificada</dt><dd>No</dd>
      </dl>
      <button type="button" onClick={download}>Exportar debrief JSON</button>
      <h3>Fallos reproducibles</h3>
      <ul>{session.scenario.scriptedSignals.map((x,i)=>
        <li key={i}>{x.source} · {x.state}: {x.message}</li>)}</ul>
      <h3>Participantes y funciones</h3>
      <ul>{session.participants.map(x=><li key={x.userId}>
        {x.userId} — {x.role} — {x.permissions} —
        {x.active?"activo":"revocado"}
      </li>)}</ul>
      {canWrite&&facilitator&&session.state!=="ARCHIVED"&&<section>
        <h3>Facilitación</h3>
        <label>ID de miembro del tenant
          <input value={person} onChange={e=>setPerson(e.target.value)}/>
        </label>
        <label>Rol simulado
          <select value={role} onChange={e=>setRole(e.target.value as Role)}>
            {ROLES.map(x=><option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        <label>Permisos de ejercicio
          <select value={permissions}
            onChange={e=>setPermissions(e.target.value as typeof permissions)}>
            <option value="PARTICIPANT">Participante</option>
            <option value="OBSERVER">Observador</option>
            <option value="FACILITATOR">Facilitador</option>
          </select>
        </label>
        <button disabled={busy||!person} type="button"
          onClick={()=>void mutate({kind:"ENROLL",participantId:person,
            role,permissions})}>Inscribir miembro</button>
        <button disabled={busy||!person} type="button"
          onClick={()=>void mutate({kind:"REMOVE",participantId:person})}>
          Revocar participación
        </button>
        <button disabled={busy||!person} type="button"
          onClick={()=>void mutate({kind:"TRANSFER_FACILITATOR",
            participantId:person})}>Transferir facilitación</button>
        {session.state==="ACTIVE"&&<button type="button" disabled={busy}
          onClick={()=>void mutate({kind:"PAUSE"})}>Pausar sesión</button>}
        {session.state==="PAUSED"&&<button type="button" disabled={busy}
          onClick={()=>void mutate({kind:"RESUME"})}>Reanudar sesión</button>}
        {["ACTIVE","PAUSED"].includes(session.state)&&
          <button type="button" disabled={busy}
            onClick={()=>void mutate({kind:"DEBRIEF"})}>Cerrar con debrief</button>}
        {session.state==="DEBRIEFED"&&<button type="button" disabled={busy}
          onClick={()=>void mutate({kind:"ARCHIVE"})}>Archivar</button>}
      </section>}
      {canWrite&&active&&session.state==="ACTIVE"&&<section>
        <h3>Ensayo de decisión</h3>
        <label>Paso del playbook
          <select value={step} onChange={e=>setStep(e.target.value)}>
            {session.scenario.activeStepIds.map(x=>
              <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        <label>Comando
          <select value={decision}
            onChange={e=>setDecision(e.target.value as Decision)}>
            {DECISIONS.map(x=><option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        <label>Justificación
          <textarea value={reason} maxLength={1000}
            onChange={e=>setReason(e.target.value)}/>
        </label>
        <button type="button" disabled={busy||reason.trim().length<5}
          onClick={()=>void mutate({kind:"PLAY",move:{
            id:"move-"+crypto.randomUUID(),stepId:step,
            actorRole:participant!.role,command:decision,reason,
            at:new Date().toISOString(),assertedIndependentEvidence:false,
            assertedExternalCompletion:false,
          }})}>Registrar decisión simulada</button>
      </section>}
      {canWrite&&active&&["ACTIVE","PAUSED"].includes(session.state)&&
        <section><h3>Notas del ejercicio</h3>
          <textarea maxLength={2000} value={note}
            onChange={e=>setNote(e.target.value)}/>
          <button type="button" disabled={busy||!note.trim()}
            onClick={()=>void mutate({kind:"NOTE",text:note})}>
            Registrar nota</button>
        </section>}
      <h3>Decisiones y rechazos</h3>
      {session.moveReceipts.length>0&&<ul>{
        session.moveReceipts.slice(showAll?0:-20).map(x=>
          <li key={x.move.id}>{x.move.stepId} · {x.move.command} ·
            {x.userId} — {x.accepted?"aceptada":"rechazada"} ({x.code})</li>)
      }</ul>}
      {session.moveReceipts.length>20&&<button type="button"
        onClick={()=>setShowAll(x=>!x)}>
        {showAll?"Reducir":"Mostrar todas las decisiones"}</button>}
      {session.debrief&&<section>
        <h3>Debrief persistido</h3>
        <p>Movimientos aceptados: {session.debrief.acceptedMoves}.
          Rechazados: {session.debrief.failedMoves}.
          Intentos inseguros: {session.debrief.unsafeAttempts}.</p>
        <p>Pasos sin ensayo aceptado: {session.debrief.unreviewedSteps.join(", ")||"ninguno"}.</p>
      </section>}
      <h3>Historial con digest encadenado</h3>
      <button type="button" onClick={()=>setShowAudit(v=>!v)}>
        {showAudit?"Ocultar":"Mostrar"} eventos</button>
      {showAudit&&<ol>{detail.events.map(e=>
        <li key={e.revision}>{e.revision} · {e.kind} · {e.actorId}
          <code>{e.eventDigest}</code>
        </li>)}</ol>}
    </section>}
  </section>;
}
