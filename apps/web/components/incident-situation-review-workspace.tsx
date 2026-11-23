"use client";
import { useCallback, useEffect, useState } from "react";
type RecordState = "OPEN" | "IN_REVIEW" | "RETURNED" | "ACKNOWLEDGED" | "SUPERSEDED";
type Review = {
  id: string; incidentId: string; revision: number; state: RecordState;
  incidentRevision: number; incidentDigest: string; situationDigest: string;
  riskBand: string; sourceUnavailable: boolean;
  concernIds: string[]; reviewerId: string | null;
  acknowledgedBy: string | null; acknowledgedAt: string | null;
  findings: Array<{id:string;concernId:string;conclusion:string;
    explanation:string;recordedBy:string}>;
  reviewNotes: string[]; updatedAt: string; externalWrites:0;
  providerContainmentVerified:false;
};
type Case = {id:string;title:string;status:string;severity:string};
type Event = {revision:number;decision:string;actorId:string;
  previousDigest:string|null;nextDigest:string;at:string};
type Detail = {review:Review;events:Event[];caseDrift:boolean;
  providerReadbackVerified:false};
type Index = {reviews:Review[];total:number;nextOffset:number|null};
type Comparison = {comparison:{caseDrift:boolean;situationDrift:boolean;
  sourceChanges:string[];addedConcerns:string[];removedConcerns:string[];
  reviewMustBeReevaluated:boolean}};
type Decision = "BEGIN_REVIEW" | "RECORD_FINDING" |
  "RETURN_FOR_EVIDENCE" | "ACKNOWLEDGE" | "REOPEN" | "SUPERSEDE";
export function IncidentSituationReviewWorkspace({slug,canWrite}:{
  slug:string;canWrite:boolean;
}) {
  const base="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/situation-reviews";
  const caseBase="/api/organizations/"+encodeURIComponent(slug)+
    "/incident-integrations/situation";
  const [cases,setCases]=useState<Case[]>([]);
  const [incidentId,setIncidentId]=useState("");
  const [items,setItems]=useState<Review[]>([]);
  const [nextOffset,setNextOffset]=useState<number|null>(null);
  const [detail,setDetail]=useState<Detail|null>(null);
  const [comparison,setComparison]=useState<Comparison|null>(null);
  const [findingConcern,setFindingConcern]=useState("");
  const [findingConclusion,setFindingConclusion]=useState<
    "CONFIRMED_GAP"|"NEEDS_EVIDENCE"|"NOT_APPLICABLE">("NEEDS_EVIDENCE");
  const [findingExplanation,setFindingExplanation]=useState("");
  const [references,setReferences]=useState("");
  const [note,setNote]=useState("");
  const [supersededBy,setSupersededBy]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [historyOpen,setHistoryOpen]=useState(false);
  const [currentOffset,setCurrentOffset]=useState(0);
  const [filter,setFilter]=useState("ALL");
  const active=detail?.review??null;
  const filtered=items.filter(x=>filter==="ALL"||x.state===filter);
  async function request<T>(url:string,method="GET",body?:unknown):Promise<T> {
    const response=await fetch(url,{
      method,cache:"no-store",
      ...(body===undefined?{}:{headers:{"Content-Type":"application/json"},
        body:JSON.stringify(body)}),
    });
    const parsed=await response.json();
    if(!response.ok)throw Error(parsed.code??"REVIEW_HTTP_"+response.status);
    return parsed.data as T;
  }
  const loadCases=useCallback(async()=>{
    const data=await request<{cases:Case[]}>(caseBase+"?mode=index&limit=100");
    setCases(data.cases);
  },[caseBase]);
  const loadIndex=useCallback(async(id:string,offset=0)=>{
    if(!id){setItems([]);setNextOffset(null);return;}
    const data=await request<Index>(base+"?"+new URLSearchParams({
      mode:"index",incidentId:id,offset:String(offset),limit:"30",
    }));
    setItems(previous=>offset?
      [...previous,...data.reviews.filter(x=>!previous.some(y=>y.id===x.id))]:
      data.reviews);
    setCurrentOffset(offset);
    setNextOffset(data.nextOffset);
  },[base]);
  const loadDetail=useCallback(async(id:string)=>{
    const data=await request<Detail>(base+"?"+new URLSearchParams({
      mode:"detail",reviewId:id,
    }));
    setDetail(data);
    setComparison(null);
    setFindingConcern(data.review.concernIds[0]??"");
  },[base]);
  useEffect(()=>{
    void loadCases().catch(e=>setError(String(e)));
  },[loadCases]);
  useEffect(()=>{
    void loadIndex(incidentId).catch(e=>setError(String(e)));
    setDetail(null);setComparison(null);
  },[incidentId,loadIndex]);
  async function operation(task:()=>Promise<void>) {
    setError("");setNotice("");setBusy(true);
    try{await task();}catch(e){setError(String(e));}
    finally{setBusy(false);}
  }
  async function create() {
    if(!incidentId)return;
    await operation(async()=>{
      const reviewId="review-"+crypto.randomUUID();
      const data=await request<{review:Review;created:boolean}>(base,"POST",{
        reviewId,selection:{incidentId,evidence:null,assets:null,
          remediation:null,consistency:"FAIL_CLOSED"},
      });
      await loadIndex(incidentId);
      await loadDetail(data.review.id);
      setNotice("Expediente persistido. Fuentes no seleccionadas: UNKNOWN; sin acciones LIVE.");
    });
  }
  async function mutate(decision:Decision) {
    if(!active)return;
    await operation(async()=>{
      const data=await request<{review:Review}>(base,"PATCH",{
        reviewId:active.id,incidentId:active.incidentId,decision,
        expectedRevision:active.revision,
        expectedSituationDigest:active.situationDigest,
        ...(decision==="RECORD_FINDING"?{
          concernId:findingConcern,conclusion:findingConclusion,
          explanation:findingExplanation.trim(),
          evidenceReferences:references.split(",").map(x=>x.trim()).filter(Boolean),
        }:{}),
        ...(decision==="RETURN_FOR_EVIDENCE"?{
          explanation:note.trim(),
        }:{}),
        ...(decision==="SUPERSEDE"?{
          supersededBy:supersededBy.trim(),
        }:{}),
      });
      await loadDetail(data.review.id);
      await loadIndex(incidentId);
      setNotice("Revisión CAS registrada en la auditoría interna. No es una verificación del proveedor.");
      setNote("");setFindingExplanation("");setReferences("");
    });
  }
  async function compare() {
    if(!active)return;
    await operation(async()=>{
      const data=await request<Comparison>(base+"?mode=invalid","GET")
        .catch(()=>null);
      void data;
      // Comparison requires an explicit selection and is exposed as a
      // service operation; until a route authorizes that operation this
      // workspace only shows the case revision drift from the persisted read.
      await loadDetail(active.id);
      setNotice("Estado de la revisión actualizado. La comparación completa de fuentes requiere una evaluación nueva.");
    });
  }
  function downloadEvidence() {
    if(!detail)return;
    const payload=JSON.stringify({
      schema:"cyberpilot.incident.situation.review.export.v1",
      exportedAt:new Date().toISOString(),
      reviewedIncident:detail.review.incidentId,
      review:detail.review,events:detail.events,
      caseDrift:detail.caseDrift,
      providerReadbackVerified:false,
      externalWrites:0,
    },null,2);
    const blob=new Blob([payload],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const anchor=document.createElement("a");
    anchor.href=url;
    anchor.download="situation-review-"+detail.review.id+".json";
    anchor.click();URL.revokeObjectURL(url);
  }
  return <section aria-label="Expedientes de revisión persistentes">
    <p role="note">Atestación interna de la sala de situación. El historial
      conserva quién revisó qué versión y cuándo. Nunca demuestra revocación,
      aislamiento, contención o ejecución de una operación externa.</p>
    <h2>Casos disponibles</h2>
    <label>Incidente
      <select value={incidentId} disabled={busy}
        onChange={e=>setIncidentId(e.target.value)}>
        <option value="">Seleccione un incidente</option>
        {cases.map(x=><option key={x.id} value={x.id}>
          {x.title} ({x.severity}, {x.status})
        </option>)}
      </select>
    </label>
    {canWrite&&<button type="button" onClick={()=>void create()}
      disabled={!incidentId||busy}>Crear expediente de revisión</button>}
    {notice&&<p role="status">{notice}</p>}
    {error&&<p role="alert">{error}</p>}
    {incidentId&&<section>
      <h2>Expedientes registrados</h2>
      <label>Filtrar estado
        <select value={filter} onChange={e=>setFilter(e.target.value)}>
          {["ALL","OPEN","IN_REVIEW","RETURNED","ACKNOWLEDGED","SUPERSEDED"]
            .map(x=><option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      {filtered.length===0?<p>No hay revisiones en esta selección.</p>:
        <ul>{filtered.map(x=><li key={x.id}>
          <button type="button" disabled={busy}
            onClick={()=>void operation(()=>loadDetail(x.id))}>
            {x.id} — {x.state} — revisión {x.revision}
          </button>
          <span> · {new Date(x.updatedAt).toLocaleString()} · {x.riskBand}</span>
        </li>)}</ul>}
      {nextOffset!==null&&<button type="button" disabled={busy}
        onClick={()=>void operation(()=>loadIndex(incidentId,nextOffset))}>
        Cargar más expedientes
      </button>}
      <p>Registros cargados: {items.length}. Página actual desde: {currentOffset}.</p>
    </section>}
    {active&&detail&&<section aria-label="Detalle auditable">
      <h2>Expediente {active.id}</h2>
      <dl>
        <dt>Estado operativo</dt><dd>{active.state}</dd>
        <dt>Versión del expediente</dt><dd>{active.revision}</dd>
        <dt>Versión del incidente</dt><dd>{active.incidentRevision}</dd>
        <dt>Evaluación de riesgo</dt><dd>{active.riskBand}</dd>
        <dt>Fuentes no observadas</dt><dd>{active.sourceUnavailable?"Sí":"No"}</dd>
        <dt>Incidente modificado posteriormente</dt>
        <dd>{detail.caseDrift?"Sí, requiere reevaluación":"No detectado en la versión consultada"}</dd>
        <dt>Contención de proveedor verificada</dt><dd>No</dd>
        <dt>Acciones externas ejecutadas</dt><dd>{active.externalWrites}</dd>
      </dl>
      <button type="button" disabled={busy} onClick={()=>void compare()}>
        Actualizar estado de origen
      </button>
      <button type="button" onClick={downloadEvidence}>Exportar expediente JSON</button>
      {comparison&&<p>Deriva de situación:
        {comparison.comparison.reviewMustBeReevaluated?"requiere revisión":"sin cambios detectados"}
      </p>}
      <h3>Preocupaciones documentadas</h3>
      {active.concernIds.length?<ul>{active.concernIds.map(x=>
        <li key={x}>{x}</li>)}</ul>:<p>Sin preocupaciones en el conjunto explícito.</p>}
      <h3>Hallazgos del revisor</h3>
      {active.findings.length?<ul>{active.findings.map(x=><li key={x.id}>
        {x.concernId} · {x.conclusion} · {x.explanation}
      </li>)}</ul>:<p>No se han registrado hallazgos.</p>}
      {canWrite&&<section>
        <h3>Acciones internas con CAS</h3>
        {["OPEN","RETURNED"].includes(active.state)&&
          <button type="button" disabled={busy}
            onClick={()=>void mutate("BEGIN_REVIEW")}>Iniciar revisión</button>}
        {active.state==="IN_REVIEW"&&<>
          <label>Preocupación
            <select value={findingConcern}
              onChange={e=>setFindingConcern(e.target.value)}>
              {active.concernIds.map(x=><option key={x} value={x}>{x}</option>)}
            </select>
          </label>
          <label>Resultado de revisión
            <select value={findingConclusion}
              onChange={e=>setFindingConclusion(e.target.value as typeof findingConclusion)}>
              <option value="NEEDS_EVIDENCE">Necesita evidencia</option>
              <option value="CONFIRMED_GAP">Brecha documentada</option>
              <option value="NOT_APPLICABLE">No aplicable a esta revisión</option>
            </select>
          </label>
          <label>Justificación del hallazgo
            <textarea maxLength={2000} value={findingExplanation}
              onChange={e=>setFindingExplanation(e.target.value)}/>
          </label>
          <label>Referencias exactas (separadas por comas)
            <input value={references} onChange={e=>setReferences(e.target.value)}/>
          </label>
          <button type="button" disabled={busy||!findingExplanation.trim()}
            onClick={()=>void mutate("RECORD_FINDING")}>
            Registrar hallazgo
          </button>
          <label>Motivo de devolución
            <textarea maxLength={2000} value={note}
              onChange={e=>setNote(e.target.value)}/>
          </label>
          <button type="button" disabled={busy||!note.trim()}
            onClick={()=>void mutate("RETURN_FOR_EVIDENCE")}>
            Devolver para nueva evidencia
          </button>
          <button type="button" disabled={busy||active.sourceUnavailable}
            onClick={()=>void mutate("ACKNOWLEDGE")}>
            Atestar revisión interna (otro revisor)
          </button>
        </>}
        {active.state==="ACKNOWLEDGED"&&<button type="button"
          disabled={busy} onClick={()=>void mutate("REOPEN")}>
          Reabrir expediente
        </button>}
        {active.state!=="SUPERSEDED"&&<>
          <label>Identificador del expediente sucesor
            <input value={supersededBy} onChange={e=>setSupersededBy(e.target.value)}/>
          </label>
          <button type="button" disabled={busy||!supersededBy.trim()}
            onClick={()=>void mutate("SUPERSEDE")}>Marcar como reemplazado</button>
        </>}
      </section>}
      <h3>Cadena de eventos de auditoría</h3>
      <button type="button" onClick={()=>setHistoryOpen(x=>!x)}>
        {historyOpen?"Ocultar":"Mostrar"} historial ({detail.events.length})
      </button>
      {historyOpen&&<ol>{detail.events.map(x=><li key={x.revision}>
        Revisión {x.revision}: {x.decision}, actor {x.actorId},
        {new Date(x.at).toLocaleString()}.
        <code>{x.nextDigest}</code>
      </li>)}</ol>}
    </section>}
  </section>;
}
