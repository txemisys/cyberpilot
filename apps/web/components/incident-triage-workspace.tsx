"use client";
import { useEffect,useState } from "react";
type TriageRow={id:string;title:string;type:string;severity:string;
  urgency:string;status:string;ownerUserId:string|null;
  overdueByMinutes:number;missingProofCategories:number;
  highImpactPending:number;reviewDueAt:string;blockers:string[];
  nextSteps:string[];stageReviews:Array<{stepId:string;title:string;
    status:string;missingSources:string[];barriers:string[]}>;
  containmentProven:false};
type Board={items:TriageRow[];total:number;truncated:boolean;
  immediate:number;overdue:number;unassigned:number;
  evidenceGaps:number;pageDigest:string};
type Page={board:Board;total:number;offset:number;nextOffset:number|null;
  artifact:{content:string}|null};
type Dossier={dossier:{reviewDecision:string;audit:{complete:boolean;
  problems:Array<{code:string;message:string}>};
  followUps:Array<{code:string;severity:string;dueAt:string;
  requiredEvidence:string[]}>;approvalReview:{selfApprovalRisks:number;
    expiredApprovals:number}};artifact:{content:string}|null};
export function IncidentTriageWorkspace({slug,mayExport}:{
  slug:string;mayExport:boolean;
}){
  const endpoint="/api/organizations/"+encodeURIComponent(slug)+"/incident-triage";
  const [rows,setRows]=useState<TriageRow[]>([]);
  const [page,setPage]=useState<Board|null>(null);
  const [nextOffset,setNextOffset]=useState<number|null>(null);
  const [selected,setSelected]=useState("");
  const [dossier,setDossier]=useState<Dossier|null>(null);
  const [artifact,setArtifact]=useState("");
  const [format,setFormat]=useState<"JSON"|"CSV"|"MARKDOWN">("JSON");
  const [message,setMessage]=useState("");
  const [busy,setBusy]=useState(false);
  const [filter,setFilter]=useState<"ALL"|"IMMEDIATE"|"OVERDUE"|
    "UNASSIGNED"|"GAPS">("ALL");
  const [workload,setWorkload]=useState<Record<string,unknown>|null>(null);
  const active=rows.find(x=>x.id===selected)??null;
  async function load(offset=0,selectedFormat?:string){
    setBusy(true);
    try{
      const q=new URLSearchParams({mode:"board",limit:"50",offset:String(offset)});
      if(selectedFormat)q.set("format",selectedFormat);
      const response=await fetch(endpoint+"?"+q,{cache:"no-store"});
      const value=await response.json();
      if(!response.ok)throw Error(value.code??"INCIDENT_TRIAGE_READ_FAILED");
      const result=value.data as Page;
      setPage(result.board);
      setRows(previous=>offset?
        [...previous,...result.board.items.filter(x=>!previous.some(y=>y.id===x.id))]:
        result.board.items);
      setNextOffset(result.nextOffset);
      if(selectedFormat)setArtifact(result.artifact?.content??"");
      setMessage("Tablero leído desde casos persistidos. Sin cambios en proveedores.");
    }catch(e){setMessage(String(e));}
    finally{setBusy(false);}
  }
  async function openDossier(id:string,selectedFormat?:string){
    setBusy(true);
    try{
      const q=new URLSearchParams({mode:"dossier",incidentId:id});
      if(selectedFormat)q.set("format",selectedFormat);
      const response=await fetch(endpoint+"?"+q,{cache:"no-store"});
      const value=await response.json();
      if(!response.ok)throw Error(value.code??"INCIDENT_DOSSIER_UNAVAILABLE");
      const result=value.data as Dossier;
      setDossier(result);setSelected(id);
      if(selectedFormat)setArtifact(result.artifact?.content??"");
      setMessage("Revisión del historial calculada sin modificar el incidente.");
    }catch(e){setMessage(String(e));}
    finally{setBusy(false);}
  }
  useEffect(()=>{
    void load();
    void fetch(endpoint+"?mode=workload",{cache:"no-store"})
      .then(r=>r.json()).then(j=>{if(j.data)setWorkload(j.data);})
      .catch(e=>setMessage(String(e)));
  },[endpoint]);
  const visible=rows.filter(x=>filter==="ALL"||
    filter==="IMMEDIATE"&&x.urgency==="IMMEDIATE"||
    filter==="OVERDUE"&&x.overdueByMinutes>0||
    filter==="UNASSIGNED"&&x.ownerUserId===null||
    filter==="GAPS"&&x.missingProofCategories>0);
  return <section aria-label="Tablero de triage">
    <p role="note">Prioridades determinadas por plazos y evidencias
      registradas, no por verificación LIVE de remediaciones.
      Los incidentes cerrados no prueban contención técnica.</p>
    <button type="button" disabled={busy} onClick={()=>void load()}>
      Actualizar triage
    </button>
    {page&&<section aria-label="Indicadores de respuesta">
      <h2>Estado de la respuesta</h2>
      <p>Observados: {page.total}; inmediatos: {page.immediate};
        fuera de plazo: {page.overdue}; sin responsable: {page.unassigned};
        cobertura incompleta: {page.evidenceGaps}.</p>
      <p>Página incompleta: {page.truncated?"sí":"no"}.</p>
      <p>Digest: {page.pageDigest}.</p>
    </section>}
    <label>Filtrar cola <select value={filter} onChange={e=>
      setFilter(e.target.value as typeof filter)}>
      <option value="ALL">Todos</option>
      <option value="IMMEDIATE">Urgentes</option>
      <option value="OVERDUE">Plazo vencido</option>
      <option value="UNASSIGNED">Sin responsable</option>
      <option value="GAPS">Faltan fuentes</option>
    </select></label>
    <h2>Incidentes priorizados</h2>
    <ol>{visible.map(x=><li key={x.id}>
      <button type="button" onClick={()=>void openDossier(x.id)}>
        {x.title} — {x.urgency} — {x.status} — {x.severity}
      </button>
      <p>Plazo vencido: {x.overdueByMinutes} minutos.
        Pendiente de fuente: {x.missingProofCategories}.
        Operaciones de alto impacto pendientes: {x.highImpactPending}.</p>
    </li>)}</ol>
    {nextOffset!==null&&<button type="button" disabled={busy}
      onClick={()=>void load(nextOffset)}>Cargar página siguiente</button>}
    {active&&dossier&&<section aria-label="Revisión del caso">
      <h2>{active.title}</h2>
      <p>Revisión: {dossier.dossier.reviewDecision}.
        Auditoría íntegra: {dossier.dossier.audit.complete?"sí":"no"}.</p>
      <p>Aprobaciones vencidas: {dossier.dossier.approvalReview.expiredApprovals};
        riesgo de autoaprobación: {dossier.dossier.approvalReview.selfApprovalRisks}.</p>
      <h3>Evidencias por paso</h3>
      <ul>{active.stageReviews.map(s=><li key={s.stepId}>
        <strong>{s.title}</strong> — {s.status}
        <p>Faltan fuentes: {s.missingSources.join(", ")||"ninguna"};
          bloqueos: {s.barriers.join(", ")||"ninguno"}.</p>
      </li>)}</ul>
      <h3>Acciones de seguimiento propuestas</h3>
      <ol>{dossier.dossier.followUps.map((f,i)=><li key={i}>
        {f.severity}: {f.code}; antes de {f.dueAt}.
        Prueba: {f.requiredEvidence.join(", ")}.
      </li>)}</ol>
      {dossier.dossier.audit.problems.length>0&&
        <h3>Problemas del historial</h3>}
      <ul>{dossier.dossier.audit.problems.map((p,i)=><li key={i}>
        {p.code}: {p.message}</li>)}</ul>
      {mayExport&&<button disabled={busy} type="button"
        onClick={()=>void openDossier(active.id,format)}>
        Preparar expediente del caso
      </button>}
    </section>}
    {mayExport&&<section aria-label="Exportar triage">
      <label>Formato <select value={format} onChange={e=>
        setFormat(e.target.value as typeof format)}>
        <option value="JSON">JSON</option>
        <option value="CSV">CSV</option>
        <option value="MARKDOWN">Markdown</option>
      </select></label>
      <button disabled={busy} type="button"
        onClick={()=>void load(0,format)}>
        Preparar tablero exportable
      </button>
      {artifact&&<textarea readOnly rows={10}
        aria-label="Exportación de triage" value={artifact}/>}
    </section>}
    {workload&&<details><summary>Carga de responsables</summary>
      <pre>{JSON.stringify(workload,null,2)}</pre>
    </details>}
    <p role="status">{message}</p>
  </section>;
}
