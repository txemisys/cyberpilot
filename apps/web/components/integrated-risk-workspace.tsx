"use client";

import { useMemo,useState } from "react";
import type {
  IntegratedRiskDigest,IntegratedRiskRow,IntegratedControlRow,
  IntegratedRiskSeverity,IntegratedEvidenceSource,
} from "../lib/integrated-risk-engine";

type Envelope={
  report:IntegratedRiskDigest;
  liveProviderCalls:0;
  legacyScoreWrites:0;
  customerApprovalSigned:false;
};
type Artifact={filename:string;mime:string;content:string};
type ExportEnvelope={
  artifact:Artifact;reportDigest:string;
  liveProviderCalls:0;legacyScoreWrites:0;
  customerApprovalSigned:false;
};
type Section="OVERVIEW"|"RISKS"|"EVIDENCE"|"SOURCES"|"QUALITY";
const sections:Array<{id:Section;label:string}>=[
  {id:"OVERVIEW",label:"Resumen"},
  {id:"RISKS",label:"Riesgos"},
  {id:"EVIDENCE",label:"Controles"},
  {id:"SOURCES",label:"Fuentes"},
  {id:"QUALITY",label:"Procedencia"},
];
const severityRank:Record<IntegratedRiskSeverity,number>={
  CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,UNKNOWN:5,
};
function safeEnvelope(data:unknown):data is Envelope{
  if(!data||typeof data!=="object"||Array.isArray(data))return false;
  const e=data as Partial<Envelope>;
  return e.liveProviderCalls===0&&e.legacyScoreWrites===0&&
    e.customerApprovalSigned===false&&
    e.report?.schema==="cyberpilot.integrated.risks.v1"&&
    typeof e.report.digest==="string"&&
    Array.isArray(e.report.risks)&&
    Array.isArray(e.report.controls)&&
    e.report.evidenceSecurityCertified===false&&
    e.report.historicalV1ScoreModified===false;
}
function fileDownload(artifact:Artifact){
  if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
    throw Error("Nombre de archivo no permitido.");
  const blob=new Blob([artifact.content],{type:artifact.mime});
  const url=URL.createObjectURL(blob);
  const link=document.createElement("a");
  link.href=url;link.download=artifact.filename;
  document.body.append(link);link.click();link.remove();
  URL.revokeObjectURL(url);
}
function severityLabel(s:IntegratedRiskSeverity){
  return s==="UNKNOWN"?"Sin clasificación":s;
}
function riskColor(s:IntegratedRiskSeverity){
  if(s==="CRITICAL"||s==="HIGH")return "#b91c1c";
  if(s==="MEDIUM")return "#a16207";
  if(s==="UNKNOWN")return "#64748b";
  return "#0f766e";
}
const box:React.CSSProperties={
  border:"1px solid #94a3b866",borderRadius:12,
  padding:18,marginBottom:16,
};
const buttons:React.CSSProperties={
  border:"1px solid #64748b88",borderRadius:8,
  padding:"8px 12px",color:"inherit",
  background:"transparent",cursor:"pointer",
};
const flex:React.CSSProperties={
  display:"flex",gap:12,flexWrap:"wrap",alignItems:"center",
};
function Metric({name,value,description}:{
  name:string;value:string|number;description?:string;
}){
  return <div style={{...box,minWidth:160,flex:"1 1 160px"}}>
    <small>{name}</small>
    <p style={{fontSize:25,fontWeight:750,margin:"6px 0"}}>{value}</p>
    {description&&<small>{description}</small>}
  </div>;
}
function EvidenceState({status}:{
  status:IntegratedControlRow["currentState"];
}){
  const healthy=status==="OBSERVED_WITH_LIMITS";
  return <span style={{color:healthy?"#0f766e":"#a16207",
    fontWeight:650}}>{status}</span>;
}
function RiskDetails({risk,onClose}:{
  risk:IntegratedRiskRow;onClose:()=>void;
}){
  return <section style={box}>
    <div style={flex}>
      <h3 style={{margin:0}}>Trazabilidad: {risk.title}</h3>
      <button style={buttons} onClick={onClose}>Cerrar detalle</button>
    </div>
    <p><strong>{severityLabel(risk.severity)}</strong> ·
      {risk.status} · {risk.evidenceState}</p>
    <p>{risk.description}</p>
    <p>Regla: <code>{risk.controlId}</code> ·
      Dominio: {risk.domain} · Scope: {risk.scope}</p>
    <p>Procedencia: {risk.source} · {risk.confidence}</p>
    <p>Último registro: {risk.observedAt??"No disponible"}</p>
    <p>Registros agrupados: {risk.deduplicatedFindingCount}</p>
    <h4>Referencias de hallazgos originales</h4>
    <ul>{risk.sourceFindingIds.map(x=><li key={x}><code>{x}</code></li>)}</ul>
    <h4>Evidencias asociadas</h4>
    {risk.sourceEvidenceIds.length===0?
      <p>No se puede asociar evidencia técnica inequívoca.</p>:
      <ul>{risk.sourceEvidenceIds.map(x=>
        <li key={x}><code>{x}</code></li>)}</ul>}
    <h4>Limitaciones particulares</h4>
    {risk.uncertainty.length===0?
      <p>Sin incidencias de enlace adicionales. No prueba remediación.</p>:
      <ul>{risk.uncertainty.map(x=><li key={x}>{x}</li>)}</ul>}
    <p><strong>Riesgo resuelto de forma independiente: NO.</strong></p>
  </section>;
}
function ControlDetails({control,onClose}:{
  control:IntegratedControlRow;onClose:()=>void;
}){
  return <section style={box}>
    <div style={flex}>
      <h3>{control.controlId}</h3>
      <button style={buttons} onClick={onClose}>Cerrar detalle</button>
    </div>
    <p>Ámbito {control.scope}, dominio {control.domain}</p>
    <p>Estado: <EvidenceState status={control.currentState}/></p>
    <p>Fuentes: {control.sources.join(", ")||"Desconocida"}</p>
    <p>Observado {control.observed} · Declarado {control.declared} ·
      Desconocido {control.unknown} · Error {control.errors} ·
      Caducado {control.stale}</p>
    <p>Primera observación: {control.earliestObservationAt??"No consta"}</p>
    <p>Última observación: {control.latestObservationAt??"No consta"}</p>
    <h4>IDs de registros persistidos</h4>
    <ul>{control.evidenceIds.map(x=><li key={x}><code>{x}</code></li>)}</ul>
    {control.hasContradictoryStates&&<p role="alert">
      Existen estados contradictorios para este control y scope.
    </p>}
    <p><strong>Scope remoto autenticado por esta vista: NO.</strong></p>
  </section>;
}
export function IntegratedRiskWorkspace({
  slug,organizationId,
}:{slug:string;organizationId:string}){
  const [data,setData]=useState<IntegratedRiskDigest|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [tab,setTab]=useState<Section>("OVERVIEW");
  const [search,setSearch]=useState("");
  const [severity,setSeverity]=useState<IntegratedRiskSeverity|"ALL">("ALL");
  const [riskState,setRiskState]=useState("ALL");
  const [source,setSource]=useState<IntegratedEvidenceSource|"ALL">("ALL");
  const [controlState,setControlState]=useState("ALL");
  const [domain,setDomain]=useState("ALL");
  const [sort,setSort]=useState<"PRIORITY"|"TITLE"|"LATEST">("PRIORITY");
  const [onlyUncertain,setOnlyUncertain]=useState(false);
  const [expandedRisk,setExpandedRisk]=useState("");
  const [expandedControl,setExpandedControl]=useState("");
  const [showCaveats,setShowCaveats]=useState(true);
  const [limit,setLimit]=useState(25);
  const [issueFilter,setIssueFilter]=useState("ALL");
  const [includeResolved,setIncludeResolved]=useState(false);
  const endpoint="/api/organizations/"+encodeURIComponent(slug)+
    "/integrated-risks";
  const load=async()=>{
    if(busy)return;
    setBusy(true);setError("");setNotice("");
    try{
      const response=await fetch(endpoint,{cache:"no-store"});
      const body:unknown=await response.json();
      if(!response.ok)throw Error("El registro no está disponible.");
      if(!safeEnvelope(body)||body.report.organizationId!==organizationId)
        throw Error("Respuesta no verificable o de otra organización.");
      setData(body.report);setExpandedRisk("");setExpandedControl("");
      setTab("OVERVIEW");setLimit(25);
      setNotice("Se han reconciliado registros persistidos de la organización.");
    }catch(cause){
      setError(cause instanceof Error?cause.message:"No se pudo consultar.");
      setData(null);
    }finally{setBusy(false);}
  };
  const exportFile=async(format:"JSON"|"CSV"|"MARKDOWN")=>{
    if(!data||busy)return;
    setBusy(true);setError("");setNotice("");
    try{
      const response=await fetch(endpoint+"?format="+format,{
        cache:"no-store",
      });
      const body=await response.json() as Partial<ExportEnvelope>;
      if(!response.ok||body.liveProviderCalls!==0||
        body.legacyScoreWrites!==0||
        body.customerApprovalSigned!==false||!body.artifact)
        throw Error("Exportación no autorizada o incompleta.");
      fileDownload(body.artifact);
      setNotice("Exportación obtenida de una nueva lectura auditada.");
    }catch(cause){
      setError(cause instanceof Error?cause.message:"Exportación fallida.");
    }finally{setBusy(false);}
  };
  const risks=useMemo(()=>{
    const needle=search.trim().toLowerCase();
    const filtered=(data?.risks??[]).filter(r=>
      (includeResolved||r.status!=="RESOLVED")&&
      (severity==="ALL"||r.severity===severity)&&
      (riskState==="ALL"||r.status===riskState)&&
      (source==="ALL"||r.source===source)&&
      (domain==="ALL"||r.domain===domain)&&
      (!onlyUncertain||r.uncertainty.length>0)&&
      (!needle||[r.title,r.controlId,r.domain,r.scope,
        r.source,r.description,...r.uncertainty]
        .join(" ").toLowerCase().includes(needle)));
    return filtered.sort((a,b)=>{
      if(sort==="TITLE")return a.title.localeCompare(b.title);
      if(sort==="LATEST")return (b.observedAt??"").localeCompare(
        a.observedAt??"");
      return severityRank[a.severity]-severityRank[b.severity]||
        a.title.localeCompare(b.title);
    });
  },[data,search,severity,riskState,source,domain,
    onlyUncertain,sort,includeResolved]);
  const controls=useMemo(()=>{
    const needle=search.trim().toLowerCase();
    return (data?.controls??[]).filter(x=>
      (controlState==="ALL"||x.currentState===controlState)&&
      (domain==="ALL"||x.domain===domain)&&
      (source==="ALL"||x.sources.includes(source))&&
      (!needle||[x.domain,x.controlId,x.scope,
        ...x.sources].join(" ").toLowerCase().includes(needle)));
  },[data,search,controlState,domain,source]);
  const issueRows=useMemo(()=>(data?.issues??[]).filter(x=>
    issueFilter==="ALL"||x.level===issueFilter),[data,issueFilter]);
  const domains=useMemo(()=>data?.coverage.controlDomains??[],[data]);
  const sources=useMemo(()=>data?.coverage.sourceFamilies??[],[data]);
  const riskDetail=risks.find(x=>x.key===expandedRisk);
  const controlDetail=controls.find(x=>x.id===expandedControl);
  return <div>
    <section style={box}>
      <h2>Registro integrado y conservador de riesgos</h2>
      <p>Consolida evidencias, hallazgos y acciones Baseline guardados
        en PostgreSQL. Una evaluación v2 sintética sigue siendo
        sintética; no cambia CyberScore histórico ni certifica la pyme.</p>
      <div style={flex}>
        <button style={buttons} disabled={busy}
          onClick={load}>Actualizar desde PostgreSQL</button>
        <button style={buttons} disabled={busy||!data}
          onClick={()=>exportFile("JSON")}>Exportar JSON</button>
        <button style={buttons} disabled={busy||!data}
          onClick={()=>exportFile("CSV")}>Exportar riesgos CSV</button>
        <button style={buttons} disabled={busy||!data}
          onClick={()=>exportFile("MARKDOWN")}>Exportar resumen</button>
      </div>
      {busy&&<p role="status">Consultando evidencias por organización…</p>}
      {error&&<p role="alert">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
    </section>
    {data&&<>
      <section style={box}>
        <div style={flex}>
          {sections.map(item=><button key={item.id}
            style={{...buttons,fontWeight:tab===item.id?750:400}}
            onClick={()=>setTab(item.id)}>{item.label}</button>)}
        </div>
        <p>Estado general: <strong>{data.state}</strong></p>
        <p>Evaluación: {data.evaluatedAt} ·
          digest <code style={{overflowWrap:"anywhere"}}>{data.digest}</code></p>
        {!data.coverage.persistedRecordsComplete&&
          <p role="alert">Se superó el límite de lectura: no se puede
            declarar completo el registro.</p>}
      </section>
      {tab==="OVERVIEW"&&<>
        <section style={flex}>
          <Metric name="Hallazgos abiertos" value={data.counts.openFindings}/>
          <Metric name="Riesgos agrupados" value={data.counts.actionableRisks}/>
          <Metric name="Controles observados" value={data.counts.controls}/>
          <Metric name="Acciones declarativas" value={data.counts.declaredActions}/>
          <Metric name="Acciones vencidas" value={data.counts.overdueDeclaredActions}/>
          <Metric name="Controles inciertos" value={
            data.counts.unknownControls+data.counts.staleControls+
            data.counts.conflictControls}/>
        </section>
        <section style={box}>
          <h3>Evaluación v2 guardada más reciente</h3>
          {data.latestAssessment?<div>
            <p>Snapshot: <code>{data.latestAssessment.snapshotId}</code></p>
            <p>Modelo: {data.latestAssessment.modelId} ·
              revisión {data.latestAssessment.revision}</p>
            <p>Origen: <strong>{data.latestAssessment.sourceClass}</strong></p>
            <p>Cobertura v2 almacenada:
              {data.latestAssessment.coveragePercent}%</p>
            <p>Score v2 almacenado:
              {data.latestAssessment.numericScore??"No evaluable"}</p>
            <p>No es puntuación histórica v1 ni acredita postura
              de seguridad de un cliente LIVE.</p>
          </div>:<p>No hay un snapshot v2 persistido.</p>}
        </section>
        <section style={box}>
          <h3>Riesgos de mayor prioridad</h3>
          {data.risks.filter(x=>x.actionNeeded).slice(0,8).map(item=>
            <p key={item.key}>
              <strong style={{color:riskColor(item.severity)}}>
                {item.severity}</strong>{" "}{item.title} ·
              {item.source} · {item.confidence}
            </p>)}
          {data.counts.actionableRisks===0&&
            <p>No hay hallazgos abiertos agrupados;
              esto no equivale a seguridad comprobada.</p>}
        </section>
      </>}
      {(tab==="RISKS"||tab==="EVIDENCE")&&
        <section style={box}>
          <h3>Filtros de {tab==="RISKS"?"riesgos":"evidencias"}</h3>
          <div style={flex}>
            <label>Buscar{" "}
              <input value={search} onChange={e=>{
                setSearch(e.target.value);setLimit(25);
              }} placeholder="Control, riesgo, alcance…"/>
            </label>
            <label>Dominio{" "}
              <select value={domain}
                onChange={e=>setDomain(e.target.value)}>
                <option value="ALL">Todos</option>
                {domains.map(x=><option key={x} value={x}>{x}</option>)}
              </select>
            </label>
            <label>Fuente{" "}
              <select value={source}
                onChange={e=>setSource(
                  e.target.value as typeof source)}>
                <option value="ALL">Todas</option>
                {sources.map(x=><option key={x} value={x}>{x}</option>)}
              </select>
            </label>
          </div>
        </section>}
      {tab==="RISKS"&&<section style={box}>
        <div style={flex}>
          <label>Gravedad{" "}
            <select value={severity}
              onChange={e=>setSeverity(
                e.target.value as typeof severity)}>
              <option value="ALL">Todas</option>
              {Object.keys(severityRank).map(x=>
                <option key={x} value={x}>{x}</option>)}
            </select>
          </label>
          <label>Estado{" "}
            <select value={riskState}
              onChange={e=>setRiskState(e.target.value)}>
              <option value="ALL">Todos</option>
              <option value="OPEN">Abiertos</option>
              <option value="RESOLVED">Resueltos (declarados)</option>
              <option value="UNKNOWN">Desconocidos</option>
            </select>
          </label>
          <label>Orden{" "}
            <select value={sort}
              onChange={e=>setSort(e.target.value as typeof sort)}>
              <option value="PRIORITY">Prioridad</option>
              <option value="TITLE">Título</option>
              <option value="LATEST">Más reciente</option>
            </select>
          </label>
          <label><input type="checkbox" checked={onlyUncertain}
            onChange={e=>setOnlyUncertain(e.target.checked)}/>
            Solo inciertos</label>
          <label><input type="checkbox" checked={includeResolved}
            onChange={e=>setIncludeResolved(e.target.checked)}/>
            Mostrar resueltos</label>
        </div>
        <p>{risks.length} riesgos. Duplicados agrupados:
          {data.counts.deduplicated}.</p>
        <ul>{risks.slice(0,limit).map(risk=><li key={risk.key}
          style={{marginBottom:15}}>
          <button style={buttons} onClick={()=>setExpandedRisk(risk.key)}>
            <strong style={{color:riskColor(risk.severity)}}>
              {risk.severity}</strong> · {risk.title}
          </button>
          <p>{risk.status} · {risk.source} ·
            {risk.confidence} · {risk.evidenceState}</p>
        </li>)}</ul>
        {risks.length>limit&&<button style={buttons}
          onClick={()=>setLimit(x=>x+25)}>Mostrar más</button>}
        {riskDetail&&<RiskDetails risk={riskDetail}
          onClose={()=>setExpandedRisk("")}/>}
      </section>}
      {tab==="EVIDENCE"&&<section style={box}>
        <label>Estado del control{" "}
          <select value={controlState}
            onChange={e=>setControlState(e.target.value)}>
            <option value="ALL">Todos</option>
            {["OBSERVED_WITH_LIMITS","DECLARED_ONLY","UNKNOWN",
              "ERROR","CONFLICT","STALE"].map(x=>
              <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
        <p>{controls.length} controles y scopes distintos.</p>
        <ul>{controls.slice(0,limit).map(x=><li key={x.id}
          style={{marginBottom:14}}>
          <button style={buttons} onClick={()=>setExpandedControl(x.id)}>
            {x.controlId} · {x.scope}
          </button>{" "}
          <EvidenceState status={x.currentState}/>
          <p>Fuentes: {x.sources.join(", ")}</p>
        </li>)}</ul>
        {controls.length>limit&&<button style={buttons}
          onClick={()=>setLimit(x=>x+25)}>Mostrar más</button>}
        {controlDetail&&<ControlDetails control={controlDetail}
          onClose={()=>setExpandedControl("")}/>}
      </section>}
      {tab==="SOURCES"&&<section style={box}>
        <h3>Procedencia de fuentes persistidas</h3>
        <ul>{sources.map(item=><li key={item}>
          <strong>{item}</strong> · {data.controls.filter(x=>
            x.sources.includes(item)).length} controles/scopes
        </li>)}</ul>
        <p>Snapshots sintéticos:
          {data.counts.syntheticAssessments} ·
          etiquetas de LIVE en registros:
          {data.counts.authenticatedLiveAssessments}.</p>
        <p>Las etiquetas de un registro no reautentican
          un tenant ni prueban consentimiento del cliente.</p>
      </section>}
      {tab==="QUALITY"&&<section style={box}>
        <h3>Calidad y límites de la conciliación</h3>
        <label>Gravedad de incidencia{" "}
          <select value={issueFilter}
            onChange={e=>setIssueFilter(e.target.value)}>
            <option value="ALL">Todas</option>
            <option value="BLOCK">Bloqueantes</option>
            <option value="WARNING">Advertencias</option>
          </select>
        </label>
        {issueRows.length===0?<p>Sin incidencias adicionales detectadas.</p>:
          <ul>{issueRows.map((x,i)=><li key={x.code+"-"+i}>
            <strong>{x.level}: {x.code}</strong>
            <p>{x.description}</p>
            {x.recordIds.length>0&&
              <small>Referencias: {x.recordIds.join(", ")}</small>}
          </li>)}</ul>}
        <p><strong>No se ha producido ninguna acción externa.</strong></p>
        <button style={buttons}
          onClick={()=>setShowCaveats(x=>!x)}>
          {showCaveats?"Ocultar":"Mostrar"} límites
        </button>
        {showCaveats&&<ul>{data.limitations.map(x=>
          <li key={x}>{x}</li>)}</ul>}
      </section>}
    </>}
  </div>;
}
