"use client";
import {useEffect,useState} from "react";
type Case={id:string;title:string;severity:string;revision:number;
  type:string;status:string};
type Assurance={
  report:{status:string;riskBand:string;riskScore:number;
    criticalFailures:number;highFailures:number;unknownControls:number;
    passedOffline:number;integrityDigest:string;
    controls:Array<{id:string;category:string;importance:string;
      state:string;reason:string;missingEvidence:string[];
      ownerRole:string;remediationGuidance:string}>};
  packet:{outstandingCount:number;prioritization:Array<{id:string;
    owner:string;action:string;deadline:string}>};
  escalation:{escalations:Array<{id:string;severity:string;
    suggestedAction:string;dueAt:string}>};
  sourceFailures:Array<{source:string;code:string}>;
  artifact:{content:string}|null;
  signoffGranted:false;
};
type Policy={schema:string;id:string;requireOwner:boolean;
  requireFullSourceScope:boolean;requireTabletopForCritical:boolean;
  requireIndependentApprovalForHighImpact:boolean;
  maxUnknownSourceCount:number;maximumPendingSteps:number;
  maxCriticalConcerns:number;allowHistoricalVerifiedAsProviderProof:false;
  minimumTabletopCoveragePercent:number;reviewIntervalHours:number};
export function IncidentAssuranceWorkspace({slug}:{slug:string}){
  const endpoint="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/assurance";
  const [cases,setCases]=useState<Case[]>([]);
  const [next,setNext]=useState<number|null>(null);
  const [incident,setIncident]=useState("");
  const [defaultPolicy,setDefaultPolicy]=useState<Policy|null>(null);
  const [policy,setPolicy]=useState<Policy|null>(null);
  const [variant,setVariant]=useState("standard");
  const [review,setReview]=useState<Assurance|null>(null);
  const [format,setFormat]=useState<"JSON"|"CSV"|"MARKDOWN">("JSON");
  const [artifact,setArtifact]=useState("");
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  async function load(offset=0){
    const response=await fetch(endpoint+"?"+new URLSearchParams({
      mode:"index",offset:String(offset),limit:"30",
    }),{cache:"no-store"});
    const body=await response.json();
    if(!response.ok)throw Error(body.code??"INDEX_FAILED");
    const rows=body.data.incidents as Case[];
    setCases(old=>offset?[...old,...rows.filter(x=>
      !old.some(y=>y.id===x.id))]:rows);
    setNext(body.data.nextOffset);
  }
  useEffect(()=>{
    void load().catch(e=>setMessage(String(e)));
    void fetch(endpoint+"?mode=policies",{cache:"no-store"})
      .then(r=>r.json()).then(body=>{
        if(body.data){
          const p=body.data.defaultPolicy as Policy;
          setDefaultPolicy(p);setPolicy(p);
        }
      }).catch(e=>setMessage(String(e)));
  },[endpoint]);
  function choosePolicy(value:string){
    setVariant(value);
    if(!defaultPolicy)return;
    if(value==="strict")setPolicy({...defaultPolicy,
      id:"strict-offline-assurance-v1",requireFullSourceScope:true,
      maxUnknownSourceCount:0,maximumPendingSteps:0,
      minimumTabletopCoveragePercent:100,reviewIntervalHours:4});
    else if(value==="investigation")setPolicy({...defaultPolicy,
      id:"investigation-offline-assurance-v1",
      requireTabletopForCritical:false,maxUnknownSourceCount:3,
      maximumPendingSteps:200,minimumTabletopCoveragePercent:60,
      reviewIntervalHours:8});
    else setPolicy(defaultPolicy);
    setReview(null);
  }
  async function evaluate(exportFormat?:typeof format){
    if(!incident||!policy){setMessage("Seleccione incidente y política");return;}
    setBusy(true);
    try{
      const response=await fetch(endpoint,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          situation:{incidentId:incident,consistency:"PARTIAL_READ",
            evidence:{evidenceIds:[],findingIds:[],decisionIds:[]},
            assets:{deviceIds:[],importIds:[],externalIds:[]},
            remediation:{remediationIds:[],findingIds:[],workItemIds:[]}},
          policy,tabletop:null,
          ...(exportFormat?{format:exportFormat}:{}),
        }),
      });
      const body=await response.json();
      if(!response.ok)throw Error(body.code??"ASSURANCE_REVIEW_FAILED");
      const result=body.data as Assurance;
      setReview(result);
      if(exportFormat)setArtifact(result.artifact?.content??"");
      setMessage("Informe de controles calculado sobre el estado actual; sin aprobación ni ejecución.");
    }catch(e){setMessage(String(e));}finally{setBusy(false);}
  }
  return <section aria-label="Auditoría de preparación ante incidentes">
    <p role="note">Revisión de controles de preparación offline.
      No crea certificaciones, no concede autorización de ejecución y
      no presume resultados de Microsoft Graph u otros proveedores.</p>
    <label>Incidente a auditar
      <select value={incident} onChange={e=>{
        setIncident(e.target.value);setReview(null);
      }}>
        <option value="">Seleccionar incidente</option>
        {cases.map(x=><option key={x.id} value={x.id}>
          {x.title} — {x.severity} — {x.status}
        </option>)}
      </select>
    </label>
    {next!==null&&<button type="button" disabled={busy}
      onClick={()=>void load(next).catch(e=>setMessage(String(e)))}>
      Más incidentes
    </button>}
    <label>Política de revisión
      <select value={variant} onChange={e=>choosePolicy(e.target.value)}>
        <option value="standard">Estándar offline</option>
        <option value="strict">Estricto preproducción</option>
        <option value="investigation">Investigación inicial</option>
      </select>
    </label>
    {policy&&<details><summary>Requisitos de la política</summary>
      <p>Fuentes desconocidas máximas: {policy.maxUnknownSourceCount}.
        Pasos pendientes máximos: {policy.maximumPendingSteps}.
        Cobertura de tabletop requerida: {policy.minimumTabletopCoveragePercent}%.
        Próxima revisión: {policy.reviewIntervalHours} horas.</p>
    </details>}
    <button type="button" disabled={busy||!policy||!incident}
      onClick={()=>void evaluate()}>Revisar controles y evidencias</button>
    {review&&<section aria-label="Expediente de preparación">
      <h2>Decisión: {review.report.status}</h2>
      <p>Riesgo operativo: {review.report.riskBand};
        índice {review.report.riskScore}.
        Fallos críticos {review.report.criticalFailures},
        fallos altos {review.report.highFailures},
        controles desconocidos {review.report.unknownControls}.</p>
      <p>Verificaciones offline completadas: {review.report.passedOffline}.
        Firma operativa concedida: NO. Contención externa: NO.</p>
      <p>Digest: {review.report.integrityDigest}.</p>
      {review.sourceFailures.length>0&&<p role="alert">
        Fuentes con error: {review.sourceFailures.map(x=>x.source).join(", ")}.
      </p>}
      <h3>Matriz de controles</h3>
      <ol>{review.report.controls.map(x=><li key={x.id}>
        <strong>{x.category} · {x.id}</strong> —
        {x.state} ({x.importance})
        <p>{x.reason}</p>
        {x.missingEvidence.length>0&&<p>
          Prueba pendiente: {x.missingEvidence.join("; ")}</p>}
        <p>Responsable: {x.ownerRole}.
          Próxima acción: {x.remediationGuidance}.</p>
      </li>)}</ol>
      <h3>Trabajo humano pendiente</h3>
      <p>{review.packet.outstandingCount} acciones para revisión.</p>
      <ol>{review.packet.prioritization.map(x=><li key={x.id}>
        {x.action} — {x.owner}, antes de {x.deadline}.
      </li>)}</ol>
      <h3>Escalados propuestos, no enviados</h3>
      <ul>{review.escalation.escalations.map(x=><li key={x.id}>
        {x.severity}: {x.suggestedAction} ({x.dueAt}).
      </li>)}</ul>
    </section>}
    <label>Formato de expediente
      <select value={format} onChange={e=>
        setFormat(e.target.value as typeof format)}>
        <option value="JSON">JSON</option><option value="CSV">CSV</option>
        <option value="MARKDOWN">Markdown</option>
      </select>
    </label>
    <button type="button" disabled={busy||!policy||!incident}
      onClick={()=>void evaluate(format)}>Preparar dossier exportable</button>
    {artifact&&<textarea readOnly rows={12}
      aria-label="Dossier de preparación" value={artifact}/>}
    <p role="status">{message}</p>
  </section>;
}
