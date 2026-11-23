"use client";
import { useEffect,useState } from "react";
type Catalog={playbooks:Array<{id:string;title:string;severity:string;
  description:string;stages:number;highImpact:number}>};
type Step={stepId:string;stageTitle:string;approvalRequired:boolean;
  risk:string;stopConditions:string[];expectedProof:string[]};
type Inject={id:string;fault:string;severity:string;
  facilitatorPrompt:string;expectedGuardrail:string};
type Result={
  scenario:{id:string;injectedFaults:string[];injectedRisk:string};
  plan:{injects:Inject[];walkthrough:Step[]};
  exercise:{acceptedMoves:number;rejectedMoves:number;
    unsafeOperationsBlocked:number;events:Array<{stepId:string;
      code:string;accepted:boolean;command:string}>};
  debrief:{readiness:string;stageCoveragePercent:number;
    safetyCompliancePercent:number;findings:Array<{code:string;
      correctiveAction:string}>;externalContainmentProven:false};
  artifact:{content:string}|null;
};
const roles=["INCIDENT_COMMANDER","SECURITY_REVIEWER",
  "IT_OPERATOR","FINANCE_APPROVER","LEGAL_REVIEWER","EVIDENCE_COLLECTOR"];
const decisions=["DECLARE_UNKNOWN","COLLECT_EVIDENCE","ESCALATE",
  "REQUEST_INDEPENDENT_APPROVAL","REQUEST_MANUAL_VERIFICATION",
  "MARK_PROVEN","SEND_PROVIDER_COMMAND"];
export function IncidentTabletopWorkspace({slug}:{slug:string}){
  const endpoint="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/tabletop";
  const [catalog,setCatalog]=useState<Catalog>({playbooks:[]});
  const [type,setType]=useState("COMPROMISED_ACCOUNT");
  const [title,setTitle]=useState("Account incident simulation");
  const [seed,setSeed]=useState(42);
  const [faultCount,setFaultCount]=useState(3);
  const [scenarioId,setScenarioId]=useState("exercise-lab-"+Date.now());
  const [moves,setMoves]=useState<Array<{id:string;stepId:string;
    actorRole:string;command:string;reason:string;at:string;
    assertedIndependentEvidence:false;assertedExternalCompletion:false}>>([]);
  const [currentStep,setCurrentStep]=useState("");
  const [role,setRole]=useState("INCIDENT_COMMANDER");
  const [decision,setDecision]=useState("DECLARE_UNKNOWN");
  const [reason,setReason]=useState("Request independent verification before action");
  const [plan,setPlan]=useState<Result|null>(null);
  const [matrix,setMatrix]=useState<Record<string,unknown>|null>(null);
  const [format,setFormat]=useState<"JSON"|"CSV"|"MARKDOWN">("JSON");
  const [artifact,setArtifact]=useState("");
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  useEffect(()=>{
    void fetch(endpoint+"?mode=catalog",{cache:"no-store"})
      .then(r=>r.json()).then(body=>{
        if(body.data)setCatalog(body.data as Catalog);
      }).catch(e=>setMessage(String(e)));
  },[endpoint]);
  async function requestMatrix(){
    setBusy(true);
    try{
      const query=new URLSearchParams({mode:"matrix",
        seed:String(seed),at:new Date().toISOString()});
      const response=await fetch(endpoint+"?"+query,{cache:"no-store"});
      const body=await response.json();
      if(!response.ok)throw Error(body.code??"MATRIX_FAILED");
      setMatrix(body.data);
      setMessage("Se ha ejercitado la matriz local de cinco playbooks.");
    }catch(e){setMessage(String(e));}finally{setBusy(false);}
  }
  async function run(exportFormat?:typeof format){
    setBusy(true);
    try{
      const now=new Date().toISOString();
      const at=moves.length?moves[0]!.at:now;
      const data={scenarioId,type,title,seed,faultCount,
        at,reviewedAt:now,additionalFaults:[],moves,
        ...(exportFormat?{format:exportFormat}:{})};
      const response=await fetch(endpoint,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify(data),
      });
      const body=await response.json();
      if(!response.ok)throw Error(body.code??"TABLETOP_FAILED");
      const result=body.data as Result;
      setPlan(result);
      if(exportFormat)setArtifact(result.artifact?.content??"");
      if(!currentStep)setCurrentStep(result.plan.walkthrough[0]?.stepId??"");
      setMessage("Simulación calculada; no se ha interactuado con ningún proveedor.");
    }catch(e){setMessage(String(e));}finally{setBusy(false);}
  }
  function addMove(){
    if(!currentStep||reason.trim().length<5){
      setMessage("Seleccione un paso y aporte una justificación.");
      return;
    }
    setMoves(old=>[...old,{
      id:"move-"+Date.now()+"-"+(old.length+1),stepId:currentStep,
      actorRole:role,command:decision,reason,
      at:new Date().toISOString(),
      assertedIndependentEvidence:false,
      assertedExternalCompletion:false,
    }]);
    setArtifact("");
    setPlan(null);
  }
  const switchType=(value:string)=>{
    setType(value);setMoves([]);setPlan(null);setCurrentStep("");
    setScenarioId("exercise-lab-"+Date.now());
  };
  return <section aria-label="Simulador de respuesta a incidentes">
    <p role="note">Ejercicios deterministas de mesa. No escriben en
      la base de datos de incidentes, no obtienen credenciales de un tenant
      y bloquean peticiones de ejecución o verificaciones simuladas.</p>
    <label>Playbook
      <select value={type} onChange={e=>switchType(e.target.value)}>
        {catalog.playbooks.map(x=><option key={x.id} value={x.id}>
          {x.title} — {x.severity}
        </option>)}
      </select>
    </label>
    <label>Título del ejercicio
      <input value={title} maxLength={180}
        onChange={e=>setTitle(e.target.value)}/>
    </label>
    <label>Semilla reproducible
      <input type="number" min={0} max={4294967295}
        value={seed} onChange={e=>setSeed(Number(e.target.value))}/>
    </label>
    <label>Fallos inyectados
      <input type="number" min={1} max={8}
        value={faultCount} onChange={e=>setFaultCount(Number(e.target.value))}/>
    </label>
    <p>Identificador de escenario: {scenarioId}.</p>
    <button type="button" disabled={busy} onClick={()=>void requestMatrix()}>
      Verificar cinco escenarios de playbook
    </button>
    <button type="button" disabled={busy} onClick={()=>void run()}>
      Generar y evaluar ejercicio offline
    </button>
    {matrix&&<details><summary>Matriz de cinco playbooks</summary>
      <pre>{JSON.stringify(matrix,null,2)}</pre>
    </details>}
    {plan&&<section aria-label="Plan y resultado del ejercicio">
      <h3>Escenario: {plan.scenario.injectedRisk}</h3>
      <p>Inyectados: {plan.scenario.injectedFaults.join(", ")}.</p>
      <h4>Incidentes simulados</h4>
      <ol>{plan.plan.injects.map(x=><li key={x.id}>
        <strong>{x.severity}: {x.fault}</strong>
        <p>{x.facilitatorPrompt}</p>
        <p>Control requerido: {x.expectedGuardrail}</p>
      </li>)}</ol>
      <h4>Pasos y controles</h4>
      <ol>{plan.plan.walkthrough.map(x=><li key={x.stepId}>
        {x.stageTitle} — {x.risk}
        <p>Detener si: {x.stopConditions.join("; ")}</p>
      </li>)}</ol>
      <h4>Revisión de formación</h4>
      <p>Estado {plan.debrief.readiness}; cobertura
        {plan.debrief.stageCoveragePercent}%;
        seguridad {plan.debrief.safetyCompliancePercent}%.</p>
      <p>Comandos rechazados: {plan.exercise.rejectedMoves};
        operaciones peligrosas bloqueadas:
        {plan.exercise.unsafeOperationsBlocked}.
        Contención real demostrada: NO.</p>
      <ul>{plan.debrief.findings.map(x=><li key={x.code}>
        {x.code}: {x.correctiveAction}
      </li>)}</ul>
      <ol>{plan.exercise.events.map((x,i)=><li key={i}>
        {x.command} / {x.stepId}: {x.code}.
      </li>)}</ol>
    </section>}
    <h3>Registrar decisiones para repetir el ejercicio</h3>
    <label>Paso
      <select value={currentStep} onChange={e=>setCurrentStep(e.target.value)}>
        <option value="">Seleccionar paso</option>
        {plan?.plan.walkthrough.map(x=><option key={x.stepId}
          value={x.stepId}>{x.stageTitle}</option>)}
      </select>
    </label>
    <label>Rol del participante
      <select value={role} onChange={e=>setRole(e.target.value)}>
        {roles.map(x=><option key={x} value={x}>{x}</option>)}
      </select>
    </label>
    <label>Decisión
      <select value={decision} onChange={e=>setDecision(e.target.value)}>
        {decisions.map(x=><option key={x} value={x}>{x}</option>)}
      </select>
    </label>
    <label>Justificación
      <textarea value={reason} rows={2}
        onChange={e=>setReason(e.target.value)}/>
    </label>
    <button type="button" disabled={busy||!plan}
      onClick={addMove}>Añadir decisión simulada</button>
    <p>Decisiones preparadas: {moves.length}.</p>
    <button type="button" disabled={busy} onClick={()=>void run()}>
      Reejecutar decisiones de mesa
    </button>
    <label>Formato
      <select value={format} onChange={e=>setFormat(e.target.value as typeof format)}>
        <option value="JSON">JSON</option><option value="CSV">CSV</option>
        <option value="MARKDOWN">Markdown</option>
      </select>
    </label>
    <button type="button" disabled={busy}
      onClick={()=>void run(format)}>Preparar debrief exportable</button>
    {artifact&&<textarea readOnly rows={10}
      aria-label="Debrief exportable" value={artifact}/>}
    <p role="status">{message}</p>
  </section>;
}
