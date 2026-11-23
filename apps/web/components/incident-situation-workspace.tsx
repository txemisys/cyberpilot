"use client";
import { useEffect, useState } from "react";
type Case = {id:string;title:string;status:string;severity:string;
  revision:number;stepsPending:number;type:string};
type Concern = {id:string;source:string;code:string;urgency:string;
  explanation:string;requiredEvidence:string[];nextStep:string;
  ownerRole:string;verifiedResolution:false};
type Situation = {riskBand:string;priorityScore:number;completeness:string;
  situationDigest:string;concerns:Concern[];
  stages:Array<{id:string;title:string;status:string;pendingSources:string[];
    approvalNeeded:boolean;approvalRecorded:boolean;remediations:number}>;
  sourceSummaries:Array<{name:string;availability:string;records:number;
    missingCount:number}>;actualContainmentVerified:false};
type Result = {situation:Situation;sourceFailures:Array<{source:string;code:string}>;
  briefing:{escalationQueue:Array<{priority:string;action:string;
    ownerRole:string;dueAt:string}>};
  reconciliation:{decision:string;mismatchCount:number};
  artifact:{content:string}|null};
export function IncidentSituationWorkspace({slug}: {slug:string}) {
  const endpoint="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/situation";
  const [cases,setCases]=useState<Case[]>([]);
  const [selected,setSelected]=useState("");
  const [nextOffset,setNextOffset]=useState<number|null>(null);
  const [linkDecision,setLinkDecision]=useState(true);
  const [consistency,setConsistency]=useState<"FAIL_CLOSED"|"PARTIAL_READ">("FAIL_CLOSED");
  const [evidence,setEvidence]=useState("");
  const [devices,setDevices]=useState("");
  const [remediations,setRemediations]=useState("");
  const [format,setFormat]=useState<"JSON"|"CSV"|"MARKDOWN">("JSON");
  const [report,setReport]=useState<Result|null>(null);
  const [artifact,setArtifact]=useState("");
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const current=cases.find(x=>x.id===selected)??null;
  async function load(offset=0) {
    const query=new URLSearchParams({mode:"index",offset:String(offset),limit:"30"});
    const response=await fetch(endpoint+"?"+query,{cache:"no-store"});
    const body=await response.json();
    if(!response.ok)throw Error(body.code??"SITUATION_INDEX_UNAVAILABLE");
    const rows=body.data.cases as Case[];
    setCases(old=>offset?[...old,...rows.filter(x=>!old.some(y=>y.id===x.id))]:rows);
    setNextOffset(body.data.nextOffset);
  }
  useEffect(()=>{void load().catch(e=>setMessage(String(e)));},[endpoint]);
  const ids=(text:string)=>text.split(",").map(x=>x.trim()).filter(Boolean);
  async function analyze(exportFormat?:typeof format) {
    if(!current) {setMessage("Seleccione un incidente");return;}
    setBusy(true);
    try {
      let relatedDecision:string|null=null;
      if(linkDecision) {
        const query=new URLSearchParams({mode:"linked",incidentId:current.id});
        const response=await fetch(endpoint+"?"+query,{cache:"no-store"});
        const body=await response.json();
        if(!response.ok)throw Error(body.code??"LINKED_DECISION_UNAVAILABLE");
        relatedDecision=body.data.linkedDecisionId??null;
      }
      const response=await fetch(endpoint,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          incidentId:current.id,consistency,
          evidence:{evidenceIds:ids(evidence),findingIds:[],
            decisionIds:relatedDecision?[relatedDecision]:[],maxAgeHours:72},
          assets:{deviceIds:ids(devices),importIds:[],
            externalIds:[],freshnessHours:72},
          remediation:{remediationIds:ids(remediations),findingIds:[],
            workItemIds:[],approvalMaxAgeHours:24},
          ...(exportFormat?{format:exportFormat}:{}),
        }),
      });
      const body=await response.json();
      if(!response.ok)throw Error(body.code??"SITUATION_REVIEW_FAILED");
      const value=body.data as Result;
      setReport(value);
      if(exportFormat)setArtifact(value.artifact?.content??"");
      setMessage("Situación calculada sobre datos persistidos sin ejecutar acciones LIVE.");
    }catch(e){setMessage(String(e));}finally{setBusy(false);}
  }
  return <section aria-label="Sala de situación del incidente">
    <p role="note">Evaluación conservadora sobre evidencias, inventario de activos
      y remediación existente. No sustituye respuesta en proveedores,
      comprobación independiente ni aprobación del cliente.</p>
    <h2>Incidentes persistidos</h2>
    <label>Incidente a coordinar
      <select value={selected} onChange={e=>{setSelected(e.target.value);setReport(null);}}>
        <option value="">Seleccione un caso</option>
        {cases.map(x=><option key={x.id} value={x.id}>
          {x.title} — {x.severity} — {x.status}
        </option>)}
      </select>
    </label>
    {nextOffset!==null&&<button type="button" disabled={busy}
      onClick={()=>void load(nextOffset).catch(e=>setMessage(String(e)))}>
      Cargar otros incidentes
    </button>}
    {current&&<p>Playbook: {current.type}; revisión {current.revision};
      pasos pendientes {current.stepsPending}.</p>}
    <label><input type="checkbox" checked={linkDecision}
      onChange={e=>setLinkDecision(e.target.checked)}/>
      Incluir decisión explícitamente asociada al incidente
    </label>
    <label>Evidencias seleccionadas por ID, separadas por comas
      <textarea rows={2} value={evidence}
        onChange={e=>setEvidence(e.target.value)}/>
    </label>
    <label>Dispositivos seleccionados por ID, separados por comas
      <textarea rows={2} value={devices}
        onChange={e=>setDevices(e.target.value)}/>
    </label>
    <label>Remediaciones seleccionadas por ID, separadas por comas
      <textarea rows={2} value={remediations}
        onChange={e=>setRemediations(e.target.value)}/>
    </label>
    <label>Política ante fallos de fuentes
      <select value={consistency} onChange={e=>
        setConsistency(e.target.value as typeof consistency)}>
        <option value="FAIL_CLOSED">Bloquear si una fuente falla</option>
        <option value="PARTIAL_READ">Devolver resultado parcial señalizado</option>
      </select>
    </label>
    <button disabled={busy||!current} type="button"
      onClick={()=>void analyze()}>Analizar situación multifuente</button>
    {report&&<section aria-label="Resultado de sala de situación">
      <h2>Prioridad {report.situation.riskBand}</h2>
      <p>Puntuación de coordinación: {report.situation.priorityScore};
        cobertura: {report.situation.completeness};
        contención real demostrada: NO.</p>
      <p>Digest del informe: {report.situation.situationDigest}.</p>
      <h3>Fuentes de CyberPilot</h3>
      <ul>{report.situation.sourceSummaries.map(x=><li key={x.name}>
        {x.name}: {x.availability}; registros {x.records};
        referencias ausentes {x.missingCount}.
      </li>)}</ul>
      {report.sourceFailures.length>0&&<p role="alert">
        Fuentes no disponibles: {report.sourceFailures.map(x=>x.source).join(", ")}
      </p>}
      <h3>Preocupaciones prioritarias</h3>
      <ol>{report.situation.concerns.map(x=><li key={x.id}>
        <strong>{x.urgency} · {x.source} · {x.code}</strong>
        <p>{x.explanation}</p>
        <p>Acción humana: {x.nextStep}; responsable {x.ownerRole};
          evidencia: {x.requiredEvidence.join("; ")||"sin fuente definida"}.</p>
      </li>)}</ol>
      <h3>Estado de los pasos del playbook</h3>
      <ol>{report.situation.stages.map(x=><li key={x.id}>
        {x.title}: {x.status}; remediaciones vinculadas {x.remediations}.
        <p>Pruebas pendientes: {x.pendingSources.join("; ")||"ninguna"};
          aprobación: {x.approvalNeeded?
          x.approvalRecorded?"registrada":"pendiente":"no requerida"}.</p>
      </li>)}</ol>
      <p>Reconciliación: {report.reconciliation.decision};
        discrepancias: {report.reconciliation.mismatchCount}.</p>
    </section>}
    <label>Formato de exportación
      <select value={format} onChange={e=>setFormat(e.target.value as typeof format)}>
        <option value="JSON">JSON</option><option value="CSV">CSV</option>
        <option value="MARKDOWN">Markdown</option>
      </select>
    </label>
    <button disabled={busy||!current} type="button"
      onClick={()=>void analyze(format)}>Preparar briefing para revisión humana</button>
    {artifact&&<textarea readOnly rows={10}
      aria-label="Briefing exportable" value={artifact}/>}
    <p role="status">{message}</p>
  </section>;
}
