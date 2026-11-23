"use client";
import { useMemo, useState } from "react";
import type {
  CaptureTimeline, TimelineExport, TimelineKindStats,
} from "../lib/offline-capture-timeline-domain";
import type { OfflineCaptureKind } from "../lib/offline-report-capture-domain";

type Envelope={
  data:{
    organizationId:string;
    report:CaptureTimeline;
    exportFile:TimelineExport|null;
    manifestDigest:string;
    page:{offset:number;limit:number;returned:number;hasMore:boolean;
      nextOffset:number|null};
    source:"PERSISTED_POSTGRESQL_CAPTURE";
    providerCalls:0;
    sqlRestorePerformed:false;
    liveCustomerAcceptance:false;
    historicalScoreV1Writes:0;
  };
  providerCalls:0;
  sqlRestorePerformed:false;
  liveCustomerAcceptance:false;
  historicalScoreV1Writes:0;
};
type AuditEnvelope={
  data:{
    organizationId:string;
    sourceGaps:Array<{kind:string;earlierId:string;laterId:string;
      elapsedMilliseconds:number}>;
    schemaDrift:Array<{kind:string;earlierId:string;laterId:string}>;
    sourceDrift:Array<{kind:string;earlierId:string;laterId:string;
      added:string[];removed:string[]}>;
    duplicateSourceIds:string[];
    incompleteIds:string[];
    integrityFailures:string[];
    truncated:boolean;
    completeHistoryAudited:boolean;
  };
  providerCalls:0;sqlRestorePerformed:false;
  liveCustomerAcceptance:false;historicalScoreV1Writes:0;
};
const card:React.CSSProperties={
  border:"1px solid #64748b66",borderRadius:12,padding:16,marginBottom:16,
};
const row:React.CSSProperties={
  display:"flex",alignItems:"center",gap:12,flexWrap:"wrap",
};
const button:React.CSSProperties={
  padding:"8px 12px",border:"1px solid #64748b88",
  background:"transparent",color:"inherit",borderRadius:8,cursor:"pointer",
};
const kinds:OfflineCaptureKind[]=[
  "INTEGRATED_RISKS","EVIDENCE_DECISIONS","EXECUTIVE","LONGITUDINAL",
];
function metric(name:string,count:number|string){
  return <div key={name} style={{...card,minWidth:130,flex:"1 1 130px"}}>
    <small>{name}</small><p><strong>{count}</strong></p></div>;
}
function download(artifact:TimelineExport){
  if(!/^[a-zA-Z0-9_.-]{1,160}$/.test(artifact.filename)||
    !["application/json","text/csv","text/markdown"].includes(artifact.mime))
    throw Error("Archivo de captura rechazado");
  const url=URL.createObjectURL(new Blob([artifact.content],
    {type:artifact.mime}));
  const anchor=document.createElement("a");
  anchor.href=url;anchor.download=artifact.filename;
  document.body.append(anchor);anchor.click();anchor.remove();
  URL.revokeObjectURL(url);
}
function asDate(raw:string){
  if(!raw)return undefined;
  const converted=new Date(raw).toISOString();
  if(!converted||Number.isNaN(Date.parse(converted)))
    throw Error("Fecha inválida");
  return converted;
}
function healthy(value:unknown,org:string):value is Envelope{
  if(!value||typeof value!=="object")return false;
  const x=value as Partial<Envelope>;
  return x.providerCalls===0&&x.sqlRestorePerformed===false&&
    x.liveCustomerAcceptance===false&&x.historicalScoreV1Writes===0&&
    x.data?.organizationId===org&&
    x.data.source==="PERSISTED_POSTGRESQL_CAPTURE"&&
    x.data.report?.organizationId===org&&
    x.data.report.providerCalls===0&&
    x.data.report.independentRemediationVerified===false&&
    x.data.report.liveCustomerAttestation===false&&
    x.data.report.cyberScoreV1Writes===0;
}
function summary(stat:TimelineKindStats){
  return <tr key={stat.kind}>
    <td>{stat.kind}</td>
    <td>{stat.count}</td><td>{stat.complete}</td>
    <td>{stat.invalid}</td><td>{stat.changes}</td>
    <td>{stat.incomparableTransitions}</td>
    <td>{stat.netRecordDelta??"No comparable"}</td>
    <td>{stat.netRiskDelta??"No comparable"}</td>
  </tr>;
}
export function OfflineCaptureTimelineWorkspace({slug,organizationId}:{
  slug:string;organizationId:string;
}){
  const [kind,setKind]=useState<OfflineCaptureKind|"ALL">("ALL");
  const [from,setFrom]=useState("");
  const [until,setUntil]=useState("");
  const [completeOnly,setCompleteOnly]=useState(false);
  const [limit,setLimit]=useState(50);
  const [offset,setOffset]=useState(0);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [data,setData]=useState<Envelope["data"]|null>(null);
  const [audit,setAudit]=useState<AuditEnvelope["data"]|null>(null);
  const [showDigests,setShowDigests]=useState(false);
  const [view,setView]=useState<"POINTS"|"CHANGES"|"QUALITY">("POINTS");
  const [search,setSearch]=useState("");
  const base="/api/organizations/"+encodeURIComponent(slug)+
    "/offline-capture-timeline";
  const execute=async(task:()=>Promise<void>)=>{
    if(busy)return;
    setBusy(true);setError("");setNotice("");
    try{await task();}
    catch(cause){setError(cause instanceof Error?
      cause.message:"No se pudo consultar la serie persistida.");}
    finally{setBusy(false);}
  };
  const parameters=(page:number,format?:string,mode?:string)=>{
    const query=new URLSearchParams();
    if(kind!=="ALL")query.set("kind",kind);
    if(from)query.set("from",asDate(from)!);
    if(until)query.set("until",asDate(until)!);
    if(completeOnly)query.set("completeOnly","true");
    query.set("limit",String(limit));query.set("offset",String(page));
    if(format)query.set("format",format);
    if(mode)query.set("view",mode);
    return query.toString();
  };
  const request=async(page:number,format?:string)=>{
    const response=await fetch(base+"?"+parameters(page,format),
      {cache:"no-store"});
    const body:unknown=await response.json();
    if(!response.ok)throw Error((body as {code?:string}).code??
      "Capturas no disponibles");
    if(!healthy(body,organizationId))
      throw Error("La respuesta no conserva el contrato seguro del tenant");
    return body.data;
  };
  const load=(page=0)=>execute(async()=>{
    const result=await request(page);
    setData(result);setOffset(page);setAudit(null);
    setNotice("Serie obtenida exclusivamente de capturas PostgreSQL.");
  });
  const loadAudit=()=>execute(async()=>{
    const res=await fetch(base+"?"+parameters(offset,undefined,"audit"),
      {cache:"no-store"});
    const body=await res.json() as Partial<AuditEnvelope>;
    if(!res.ok)throw Error((body as {code?:string}).code??
      "Auditoría rechazada");
    if(body.providerCalls!==0||body.sqlRestorePerformed!==false||
      body.liveCustomerAcceptance!==false||body.historicalScoreV1Writes!==0||
      body.data?.organizationId!==organizationId)
      throw Error("Auditoría con alcance inválido");
    setAudit(body.data);setView("QUALITY");
    setNotice("Anomalías derivadas únicamente de archivos persistidos.");
  });
  const exportAs=(format:"JSON"|"CSV"|"MARKDOWN")=>execute(async()=>{
    const result=await request(offset,format);
    const artifact=result.exportFile;
    if(!artifact)throw Error("No se generó el archivo");
    download(artifact);
    setNotice(artifact.completenessWarning?
      "Exportación parcial o con fuentes incompletas; no certificar.":
      "Exportación verificada de la página actual.");
  });
  const points=useMemo(()=>data?.report.points.filter(x=>
    !search||[x.id,x.kind,x.reportSchema,...x.sourceClasses]
      .join(" ").toLowerCase().includes(search.toLowerCase()))??[],
    [data,search]);
  const totals=useMemo(()=>({
    complete:points.filter(x=>x.sourceComplete).length,
    invalid:points.filter(x=>!x.integrityValid).length,
    changed:data?.report.changes.filter(x=>x.historicalChangeObserved).length??0,
  }),[data,points]);
  return <div>
    <section style={card}>
      <h2>Serie histórica de capturas archivadas</h2>
      <p>Las series proceden de capturas inmutables; no interpolan periodos
      sin evidencia. Los cambios numéricos no demuestran remediación ni
      seguridad LIVE. Las comparaciones de versión o fuente incompleta
      se marcan explícitamente como no comparables.</p>
      <div style={row}>
        <label>Familia de informe{" "}
          <select value={kind} onChange={e=>{
            setKind(e.target.value as typeof kind);setOffset(0);}}>
            <option value="ALL">Todas</option>
            {kinds.map(x=><option key={x} value={x}>{x}</option>)}
          </select></label>
        <label>Desde{" "}
          <input type="datetime-local" value={from}
            onChange={e=>setFrom(e.target.value)}/></label>
        <label>Hasta{" "}
          <input type="datetime-local" value={until}
            onChange={e=>setUntil(e.target.value)}/></label>
        <label>Por página{" "}
          <select value={limit} onChange={e=>setLimit(Number(e.target.value))}>
            {[25,50,100,200].map(x=><option key={x}>{x}</option>)}
          </select></label>
        <label><input type="checkbox" checked={completeOnly}
          onChange={e=>setCompleteOnly(e.target.checked)}/>
          Solo fuentes completas</label>
      </div>
      <div style={row}>
        <button style={button} disabled={busy} onClick={()=>load()}>
          Consultar histórico</button>
        <button style={button} disabled={busy||!data} onClick={loadAudit}>
          Auditar serie</button>
        {(["JSON","CSV","MARKDOWN"] as const).map(x=>
          <button key={x} style={button} disabled={busy||!data}
            onClick={()=>exportAs(x)}>Exportar {x}</button>)}
      </div>
      {busy&&<p role="status">Verificando archivos y procedencia…</p>}
      {error&&<p role="alert">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
    </section>
    {data&&<>
      <section style={row}>
        {metric("Capturas en página",points.length)}
        {metric("Fuentes completas",totals.complete)}
        {metric("Integridad inválida",totals.invalid)}
        {metric("Cambios comparables",totals.changed)}
      </section>
      {data.report.truncated&&<p role="alert">
        La consulta está paginada; las métricas no cubren el historial entero.
      </p>}
      <section style={card}>
        <p>Manifiesto: <code>{data.manifestDigest}</code></p>
        <div style={row}>{(["POINTS","CHANGES","QUALITY"] as const)
          .map(x=><button key={x} style={button} onClick={()=>setView(x)}>
            {x}</button>)}</div>
        <label><input type="checkbox" checked={showDigests}
          onChange={e=>setShowDigests(e.target.checked)}/>
          Mostrar huellas locales</label>
      </section>
      {view==="POINTS"&&<section style={card}>
        <h3>Capturas archivadas</h3>
        <label>Filtrar esta página{" "}
          <input value={search} onChange={e=>setSearch(e.target.value)}/>
        </label>
        <ol>{points.map(x=><li key={x.id}>
          <p><strong>{x.kind}</strong> · {x.createdAt} · {x.reportSchema}</p>
          <p>Registros: {x.recordCount} · riesgos: {x.riskCount} ·
          clases de fuente: {x.sourceClassCount}</p>
          <p>Fuente completa: {String(x.sourceComplete)} ·
          integridad: {x.integrityValid?"Válida":"RECHAZADA"} ·
          origen repetido: {String(x.duplicatedDigest)}</p>
          {showDigests&&<p><code>{x.reportDigest}</code> /
          <code>{x.payloadDigest}</code></p>}
        </li>)}</ol>
      </section>}
      {view==="CHANGES"&&<section style={card}>
        <h3>Comparaciones contiguas dentro de esta página</h3>
        {data.report.changes.length===0&&<p>
          No hay pares en la página para comparar.</p>}
        <ol>{data.report.changes.map(x=><li
          key={x.earlierId+"-"+x.laterId}>
          <p>{x.kind} · {x.earlierAt} → {x.laterAt}</p>
          {x.comparable?<p>
            Δ registros {x.recordCountDelta}, Δ riesgos {x.riskCountDelta};
            origen modificado: {String(x.digestChanged)}
          </p>:<p role="alert">
            No comparable: {x.reasons.join(", ")}
          </p>}
          {x.comparable&&<p>
            Clases añadidas: {x.sourceClassesAdded.join(", ")||"ninguna"};
            retiradas: {x.sourceClassesRemoved.join(", ")||"ninguna"}.
          </p>}
        </li>)}</ol>
      </section>}
      {view==="QUALITY"&&<section style={card}>
        <h3>Conservación y coherencia por familia</h3>
        <div style={{overflowX:"auto"}}>
          <table><thead><tr><th>Familia</th><th>Total</th>
            <th>Completas</th><th>Inválidas</th><th>Cambios</th>
            <th>No comparables</th><th>Δ registros</th>
            <th>Δ riesgos</th></tr></thead>
            <tbody>{data.report.kinds.map(summary)}</tbody></table>
        </div>
        {audit&&<div>
          <h4>Auditoría de fuentes persistidas</h4>
          <p>Gaps prolongados: {audit.sourceGaps.length} ·
          esquemas cambiados: {audit.schemaDrift.length} ·
          familias de evidencia modificadas: {audit.sourceDrift.length}</p>
          <p>Capturas incompletas: {audit.incompleteIds.length} ·
          huellas inválidas: {audit.integrityFailures.length} ·
          origen duplicado: {audit.duplicateSourceIds.length}</p>
          {!audit.completeHistoryAudited&&<p role="alert">
            La auditoría no demuestra integridad completa del historial.
          </p>}
        </div>}
      </section>}
      <section style={row}>
        <button style={button} disabled={busy||offset===0}
          onClick={()=>load(Math.max(0,offset-limit))}>
          Página anterior</button>
        <span>Offset {offset}, tamaño {data.page.returned}</span>
        <button style={button} disabled={busy||!data.page.hasMore}
          onClick={()=>load(data.page.nextOffset??offset)}>
          Página siguiente</button>
      </section>
    </>}
  </div>;
}
