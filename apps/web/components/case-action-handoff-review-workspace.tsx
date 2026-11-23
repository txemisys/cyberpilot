"use client";
import { useMemo,useState } from "react";
import type {
  CaseActionHandoffBoard,HandoffBoardPage,
} from "../lib/case-action-handoff-domain";
type Result={
  organizationId:string;
  board:CaseActionHandoffBoard;
  page:HandoffBoardPage;
  artifact:{filename:string;mime:string;content:string}|null;
  sourceSnapshots:{
    evidenceCases:number;riskActions:number;availableRisks:number;
    sourceTruncated:boolean;riskReportDigest:string;
  };
  providerCalls:0;independentRemediationConfirmed:false;
  LIVEPermissionGranted:false;customerConsentCreated:false;
  cyberScoreV1Writes:0;
};
type Envelope={
  data:Result;
  providerCalls:0;independentRemediationConfirmed:false;
  LIVEPermissionGranted:false;customerConsentCreated:false;
  cyberScoreV1Writes:0;
};
const card:React.CSSProperties={
  border:"1px solid #94a3b866",borderRadius:12,
  padding:18,marginBottom:16,
};
const row:React.CSSProperties={
  display:"flex",flexWrap:"wrap",alignItems:"center",gap:12,
};
const button:React.CSSProperties={
  border:"1px solid #64748b88",borderRadius:8,
  background:"transparent",color:"inherit",padding:"8px 12px",cursor:"pointer",
};
function verified(x:unknown,org:string):x is Envelope{
  if(!x||typeof x!=="object")return false;
  const value=x as Partial<Envelope>;
  return value.providerCalls===0&&
    value.independentRemediationConfirmed===false&&
    value.LIVEPermissionGranted===false&&
    value.customerConsentCreated===false&&
    value.cyberScoreV1Writes===0&&
    value.data?.organizationId===org&&
    value.data.board?.organizationId===org&&
    value.data.board.LIVEProviderCalls===0&&
    value.data.board.independentRemediationVerified===false&&
    value.data.board.customerConsentEstablished===false&&
    value.data.board.scoreV1Writes===0;
}
function save(artifact:{filename:string;mime:string;content:string}){
  if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename)||
    !["application/json","text/csv","text/markdown"].includes(artifact.mime))
    throw Error("Expediente rechazado");
  const link=document.createElement("a");
  const uri=URL.createObjectURL(new Blob([artifact.content],{
    type:artifact.mime,
  }));
  link.href=uri;link.download=artifact.filename;
  document.body.append(link);link.click();link.remove();
  URL.revokeObjectURL(uri);
}
export function CaseActionHandoffReviewWorkspace({slug,organizationId}:{
  slug:string;organizationId:string;
}){
  const [kind,setKind]=useState("ALL");
  const [search,setSearch]=useState("");
  const [owner,setOwner]=useState("");
  const [priority,setPriority]=useState("ALL");
  const [limit,setLimit]=useState(25);
  const [offset,setOffset]=useState(0);
  const [busy,setBusy]=useState(false);
  const [notice,setNotice]=useState("");
  const [error,setError]=useState("");
  const [data,setData]=useState<Result|null>(null);
  const [selected,setSelected]=useState("");
  const route="/api/organizations/"+encodeURIComponent(slug)+
    "/case-action-review";
  const params=(page:number,format?:string)=>{
    const query=new URLSearchParams();
    query.set("kind",kind);
    query.set("offset",String(page));
    query.set("limit",String(limit));
    if(search.trim())query.set("search",search.trim());
    if(owner.trim())query.set("owner",owner.trim());
    if(priority!=="ALL")query.set("priority",priority);
    if(format)query.set("format",format);
    return query.toString();
  };
  const execute=async(task:()=>Promise<void>)=>{
    if(busy)return;
    setBusy(true);setNotice("");setError("");
    try{await task();}
    catch(cause){setError(cause instanceof Error?cause.message:
      "Revisión no disponible");}
    finally{setBusy(false);}
  };
  const load=async(page=0,format?:string)=>{
    const response=await fetch(route+"?"+params(page,format),{
      cache:"no-store",
    });
    const body:unknown=await response.json();
    if(!response.ok)throw Error((body as {code?:string}).code??
      "Informe no accesible");
    if(!verified(body,organizationId))
      throw Error("Origen o contrato de seguridad incompatibles");
    return body.data;
  };
  const refresh=(page=0)=>execute(async()=>{
    const result=await load(page);
    setData(result);setOffset(page);setSelected("");
    setNotice("Casos y riesgos reconciliados con PostgreSQL.");
  });
  const exportAs=(format:"JSON"|"CSV"|"MARKDOWN")=>execute(async()=>{
    const result=await load(offset,format);
    if(!result.artifact)throw Error("Exportación vacía");
    save(result.artifact);
    setNotice("Expediente exportado sin autorización LIVE.");
  });
  const active=useMemo(()=>data?.page.rows.find(x=>x.caseId===selected),
    [data,selected]);
  return <div>
    <section style={card}>
      <h2>Conciliación de casos con acciones de riesgo</h2>
      <p>El sistema examina los hallazgos originales y únicamente propone
      riesgos persistidos de la misma organización. La creación final
      se realiza desde el caso mediante transacción atómica con CAS.</p>
      <div style={row}>
        <label>Estado{" "}
          <select value={kind} onChange={e=>setKind(e.target.value)}>
            {["ALL","READY","BLOCKED","LINKED","UNLINKED"].map(x=>
              <option key={x} value={x}>{x}</option>)}
          </select></label>
        <label>Buscar{" "}
          <input value={search} onChange={e=>setSearch(e.target.value)}/>
        </label>
        <label>Owner{" "}
          <input value={owner} onChange={e=>setOwner(e.target.value)}/>
        </label>
        <label>Prioridad máxima{" "}
          <select value={priority} onChange={e=>setPriority(e.target.value)}>
            {["ALL","P0","P1","P2","P3"].map(x=>
              <option key={x} value={x}>{x}</option>)}
          </select></label>
        <label>Tamaño{" "}
          <select value={limit} onChange={e=>setLimit(Number(e.target.value))}>
            {[25,50,100,200].map(x=><option key={x}>{x}</option>)}
          </select></label>
      </div>
      <div style={row}>
        <button style={button} disabled={busy} onClick={()=>refresh()}>
          Conciliar con fuentes persistidas</button>
        {(["JSON","CSV","MARKDOWN"] as const).map(x=>
          <button key={x} style={button} disabled={!data||busy}
            onClick={()=>exportAs(x)}>Exportar {x}</button>)}
      </div>
      {busy&&<p role="status">Validando hallazgos y links…</p>}
      {error&&<p role="alert">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
    </section>
    {data&&<>
      <section style={card}>
        <h3>Resumen de trazabilidad</h3>
        <div style={row}>
          <span>Casos: {data.board.totals.cases}</span>
          <span>Acciones enlazadas: {data.board.totals.linked}</span>
          <span>Preparados: {data.board.totals.readyForHandoff}</span>
          <span>Sin hallazgos: {data.board.totals.withoutOriginalFindings}</span>
          <span>Vínculos huérfanos: {data.board.totals.orphanedLinks}</span>
          <span>Fuentes ambiguas: {data.board.totals.ambiguousSources}</span>
        </div>
        <p>Estado del origen: <strong>{data.board.status}</strong>.</p>
        {data.board.sourceTruncated&&<p role="alert">
          Orígenes truncados: no se autoriza crear acciones automáticamente.
        </p>}
        {data.board.issues.length>0&&<p role="alert">
          {data.board.issues.join(", ")}
        </p>}
        <p>Digest del registro de riesgos:{" "}
          <code>{data.board.riskReportDigest}</code></p>
      </section>
      <section style={card}>
        <h3>Casos y riesgos posibles</h3>
        <ol>{data.page.rows.map(x=><li key={x.caseId}>
          <button style={button} onClick={()=>setSelected(x.caseId)}>
            {x.casePriority} · {x.caseStatus} · {x.caseId}</button>
          <p>Riesgos compatibles: {x.candidateCount} ·
            transacción habilitada: {String(x.safeForHandoff)} ·
            revisión CAS: {x.caseRevision}</p>
        </li>)}</ol>
        <div style={row}>
          <button style={button} disabled={busy||offset===0}
            onClick={()=>refresh(Math.max(0,offset-limit))}>
            Anterior</button>
          <span>Resultados: {data.page.total} · offset {offset}</span>
          <button style={button}
            disabled={busy||data.page.nextOffset===null}
            onClick={()=>refresh(data.page.nextOffset??offset)}>
            Siguiente</button>
        </div>
      </section>
      {active&&<section style={card}>
        <h3>Linaje del caso {active.caseId}</h3>
        <p>Decisión: <code>{active.decisionKey}</code></p>
        <p>Fuente histórica: <code>{active.decisionSourceDigest}</code></p>
        <p>Hallazgos originales: {active.originalFindingCount};
          evidencias originales: {active.originalEvidenceCount}</p>
        <p>Acción actual: {active.relatedActionId??"Ninguna"} ·
          vinculada al hallazgo: {String(active.linkedActionSourceMatched)}</p>
        {active.orphanedRelatedAction&&<p role="alert">
          El enlace apunta a una acción no encontrada en la lectura acotada.
        </p>}
        <h4>Riesgos correlacionados</h4>
        {active.candidates.length===0?<p>
          No se encontró ningún riesgo del origen compatible.</p>:
          <ul>{active.candidates.map(x=><li key={x.riskKey}>
            <strong>{x.severity} · {x.title}</strong>
            <p>Hallazgos coincidentes: {x.sharedFindingIds.length};
              evidencias coincidentes: {x.sharedEvidenceIds.length}</p>
            <p>Acción preexistente: {x.existingActionId??"Ninguna"}</p>
            <p>Eligible: {String(x.supportsAtomicHandoff)} ·
              {x.unsupportedReason??"Origen compatible"}</p>
          </li>)}</ul>}
        <p><a href={"/organizations/"+encodeURIComponent(slug)+
          "/decision-cases"}>Abrir caso para crear o enlazar su acción</a></p>
      </section>}
    </>}
  </div>;
}
