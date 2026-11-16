"use client";
import {useMemo,useState} from "react";
import type {
  ExecutiveCockpitReport,ExecutiveCockpitRisk,ExecutiveCockpitCoverage,
  ExecutiveCockpitSection,
} from "../lib/integrated-executive-cockpit";
type Envelope={
  report:ExecutiveCockpitReport;externalProviderCalls:0;
  acceptedCustomerRisk:false;legacyScoreChanged:false;
  independentlyVerifiedRemediation:false;
};
type ExportEnvelope={
  artifact:{filename:string;mime:string;content:string};
  externalProviderCalls:0;acceptedCustomerRisk:false;
  legacyScoreChanged:false;
  independentlyVerifiedRemediation:false;
};
type Tab="SUMMARY"|"RISK"|"COVERAGE"|"FOLLOW_UP"|"AUDIT"|"LIMITS";
const tabs:Array<{id:Tab;label:string}>=[
  {id:"SUMMARY",label:"Resumen"},
  {id:"RISK",label:"Riesgos"},
  {id:"COVERAGE",label:"Cobertura"},
  {id:"FOLLOW_UP",label:"Seguimiento"},
  {id:"AUDIT",label:"Integridad"},
  {id:"LIMITS",label:"Límites"},
];
const card:React.CSSProperties={
  border:"1px solid #94a3b866",borderRadius:12,
  padding:18,marginBottom:16,
};
const button:React.CSSProperties={
  border:"1px solid #64748b88",background:"transparent",
  color:"inherit",borderRadius:8,padding:"8px 12px",cursor:"pointer",
};
const flow:React.CSSProperties={
  display:"flex",gap:12,flexWrap:"wrap",alignItems:"center",
};
function object(x:unknown):x is Record<string,unknown>{
  return x!==null&&typeof x==="object"&&!Array.isArray(x);
}
function validEnvelope(x:unknown,organizationId:string):x is Envelope{
  if(!object(x)||!object(x.report))return false;
  const v=x as Envelope;
  const r=v.report;
  return v.externalProviderCalls===0&&
    v.acceptedCustomerRisk===false&&
    v.legacyScoreChanged===false&&
    v.independentlyVerifiedRemediation===false&&
    r.schema==="cyberpilot.executive.cockpit.v1"&&
    r.organizationId===organizationId&&
    r.historicalCyberScoreRewritten===false&&
    r.customerCertificationGranted===false&&
    r.technicalRemediationExecuted===false&&
    r.independentCustomerApprovalProven===false&&
    r.externalProviderCalls===0&&
    Array.isArray(r.risks)&&Array.isArray(r.sections);
}
function saveExport(artifact:ExportEnvelope["artifact"]){
  if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
    throw Error("Nombre de archivo no permitido");
  const url=URL.createObjectURL(new Blob([artifact.content],
    {type:artifact.mime}));
  const anchor=document.createElement("a");
  anchor.href=url;anchor.download=artifact.filename;
  document.body.append(anchor);anchor.click();anchor.remove();
  URL.revokeObjectURL(url);
}
function humanVerdict(value:string){
  if(value==="NO_PERSISTED_EVIDENCE")return"Sin evidencia persistida";
  if(value==="INCOMPLETE")return"Datos incompletos";
  return"Requiere revisión";
}
function riskColor(severity:string){
  if(["CRITICAL","HIGH"].includes(severity))return"#b91c1c";
  if(severity==="MEDIUM")return"#a16207";
  return"#64748b";
}
function Metric({label,value,hint}:{
  label:string;value:number|string;hint?:string;
}){
  return <div style={{...card,minWidth:150,flex:"1 1 150px"}}>
    <small>{label}</small>
    <p style={{fontSize:26,fontWeight:750,margin:"6px 0"}}>
      {value}
    </p>
    {hint&&<small>{hint}</small>}
  </div>;
}
function SectionSummary({section}:{
  section:ExecutiveCockpitSection;
}){
  const color=section.state==="INCOMPLETE"?"#a16207":
    section.state==="REQUIRES_ATTENTION"?"#b91c1c":"#0f766e";
  return <article style={card}>
    <h3>{section.title}</h3>
    <p style={{color,fontWeight:700}}>{section.state}</p>
    <p>{section.narrative}</p>
    <p>Registros: {section.total} · sin verificación suficiente:
      {section.uncertain} · de atención prioritaria:
      {section.critical}</p>
  </article>;
}
function RiskRow({risk,open,onClick}:{
  risk:ExecutiveCockpitRisk;open:boolean;onClick:()=>void;
}){
  return <li style={{marginBottom:14}}>
    <button style={button} onClick={onClick}>
      <strong style={{color:riskColor(risk.severity)}}>
        {risk.severity}</strong>{" "}{risk.title}
    </button>
    <p>{risk.status} · {risk.source} · {risk.domain} ·
      {risk.actionState??"Sin seguimiento"}</p>
    {risk.isOverdue&&<p style={{color:"#b91c1c"}}>
      Seguimiento vencido: {risk.dueAt}</p>}
    {open&&<section style={card}>
      <p>Risk key: <code>{risk.riskKey}</code></p>
      <p>Hallazgos originales: {risk.sourceFindingCount} ·
        evidencias: {risk.evidenceCount}</p>
      <p>Última observación: {risk.lastObservedAt??"No consta"}</p>
      <p>Responsable: {risk.ownerUserId??"No asignado"}</p>
      <p>Estado de acción: {risk.actionState??"SIN ACCIÓN"}</p>
      <p>Revisión CAS: {risk.actionRevision??"No aplicable"}</p>
      <p>Motivos de incertidumbre:
        {risk.uncertainty.join(", ")||"Sin alertas añadidas"}</p>
      <p>Acción comunicada como completada:
        {risk.actionCompletedReported?"Sí (declaración)":"No"}</p>
      <p><strong>Remediación técnica verificada: NO.</strong></p>
    </section>}
  </li>;
}
function CoverageRow({item}:{
  item:ExecutiveCockpitCoverage;
}){
  return <tr>
    <td>{item.domain}</td>
    <td>{item.controls}</td>
    <td>{item.observedWithLimits}</td>
    <td>{item.declaredOnly}</td>
    <td>{item.unknown+item.stale+item.conflicting+item.errors}</td>
    <td>{item.observedPercent}% (registro, no cobertura certificada)</td>
  </tr>;
}
export function IntegratedExecutiveWorkspace({
  slug,organizationId,
}:{slug:string;organizationId:string}){
  const [report,setReport]=useState<ExecutiveCockpitReport|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [tab,setTab]=useState<Tab>("SUMMARY");
  const [query,setQuery]=useState("");
  const [severity,setSeverity]=useState("ALL");
  const [actionState,setActionState]=useState("ALL");
  const [domain,setDomain]=useState("ALL");
  const [sort,setSort]=useState<"PRIORITY"|"DUE"|"NAME">("PRIORITY");
  const [onlyOverdue,setOnlyOverdue]=useState(false);
  const [onlyWithoutAction,setOnlyWithoutAction]=useState(false);
  const [selected,setSelected]=useState("");
  const [limit,setLimit]=useState(25);
  const [includeSources,setIncludeSources]=useState(true);
  const [showProvenance,setShowProvenance]=useState(false);
  const [showSections,setShowSections]=useState(true);
  const [showCaveats,setShowCaveats]=useState(true);
  const [auditSearch,setAuditSearch]=useState("");
  const route="/api/organizations/"+encodeURIComponent(slug)+
    "/integrated-executive";
  const load=async()=>{
    if(busy)return;
    setBusy(true);setError("");setNotice("");
    try{
      const response=await fetch(route,{cache:"no-store"});
      const body:unknown=await response.json();
      if(!response.ok||!validEnvelope(body,organizationId))
        throw Error("Informe ejecutivo incompleto o de otro tenant.");
      setReport(body.report);setSelected("");setTab("SUMMARY");
      setNotice("Panel reconstruido desde los registros persistidos.");
    }catch(cause){
      setReport(null);setError(cause instanceof Error?cause.message:
        "No se pudo generar el panel.");
    }finally{setBusy(false);}
  };
  const exportFile=async(format:"JSON"|"CSV"|"MARKDOWN")=>{
    if(!report||busy)return;
    setBusy(true);setError("");setNotice("");
    try{
      const response=await fetch(route+"?format="+format,
        {cache:"no-store"});
      const result=await response.json() as Partial<ExportEnvelope>;
      if(!response.ok||!result.artifact||
        result.externalProviderCalls!==0||
        result.legacyScoreChanged!==false||
        result.acceptedCustomerRisk!==false||
        result.independentlyVerifiedRemediation!==false)
        throw Error("No se puede exportar un informe no verificable.");
      saveExport(result.artifact);
      setNotice("Exportado un informe recién calculado sin conexión LIVE.");
    }catch(cause){
      setError(cause instanceof Error?cause.message:
        "Error exportando el informe.");
    }finally{setBusy(false);}
  };
  const risks=useMemo(()=>{
    const needle=query.toLowerCase().trim();
    const filtered=(report?.risks??[]).filter(x=>
      (severity==="ALL"||x.severity===severity)&&
      (actionState==="ALL"||
        (actionState==="NONE"&&x.actionState===null)||
        x.actionState===actionState)&&
      (domain==="ALL"||x.domain===domain)&&
      (!onlyOverdue||x.isOverdue)&&
      (!onlyWithoutAction||x.actionId===null)&&
      (!needle||[
        x.title,x.riskKey,x.domain,x.source,
        x.ownerUserId??"",x.actionState??"",
      ].join(" ").toLowerCase().includes(needle)));
    return [...filtered].sort((a,b)=>{
      if(sort==="NAME")return a.title.localeCompare(b.title);
      if(sort==="DUE")return(a.dueAt??"9999").localeCompare(
        b.dueAt??"9999");
      return a.priorityRank-b.priorityRank||
        a.title.localeCompare(b.title);
    });
  },[report,severity,actionState,domain,onlyOverdue,
    onlyWithoutAction,query,sort]);
  const sections=useMemo(()=>report?.sections??[],[report]);
  const coverage=useMemo(()=>report?.coverage??[],[report]);
  const qualityIssues=useMemo(()=>
    (report?.audit.actionAuditIssues??[]).filter(x=>
      x.toLowerCase().includes(auditSearch.toLowerCase())),
  [report,auditSearch]);
  return <div>
    <section style={card}>
      <h2>Cuadro ejecutivo · operación sin tenants externos</h2>
      <p>Este panel es una composición de evidencias ya persistidas
        y de acciones humanas. No ejecuta proveedores, no promueve
        CyberScore v2 a producción y no representa conformidad
        certificada con ningún marco.</p>
      <div style={flow}>
        <button style={button} disabled={busy}
          onClick={load}>Generar informe desde PostgreSQL</button>
        <button style={button} disabled={!report||busy}
          onClick={()=>exportFile("JSON")}>Exportar JSON</button>
        <button style={button} disabled={!report||busy}
          onClick={()=>exportFile("CSV")}>Exportar tabla CSV</button>
        <button style={button} disabled={!report||busy}
          onClick={()=>exportFile("MARKDOWN")}>Exportar Markdown</button>
      </div>
      {busy&&<p role="status">Conciliando riesgos y seguimiento…</p>}
      {error&&<p role="alert">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
    </section>
    {report&&<>
      <section style={card}>
        <div style={flow}>
          {tabs.map(x=><button key={x.id}
            style={{...button,fontWeight:tab===x.id?750:400}}
            onClick={()=>setTab(x.id)}>{x.label}</button>)}
        </div>
        <h3>Estado: {humanVerdict(report.verdict)}</h3>
        <p>Informe: {report.reportId} · {report.generatedAt}</p>
        <p>SHA-256 local: <code style={{overflowWrap:"anywhere"}}>
          {report.digest}</code></p>
        {report.verdict==="INCOMPLETE"&&<p role="alert">
          Hay fuentes incompletas o incidencias de auditoría.
          No se debe inferir que la organización está segura.</p>}
      </section>
      {tab==="SUMMARY"&&<>
        <section style={flow}>
          <Metric label="Riesgos abiertos"
            value={report.summary.openRisks}/>
          <Metric label="Alta prioridad"
            value={report.summary.highPriorityOpenRisks}/>
          <Metric label="Sin plan" value={
            report.summary.unresolvedWithoutActions}/>
          <Metric label="Acciones vencidas"
            value={report.summary.overdueActions}/>
          <Metric label="Bloqueadas"
            value={report.summary.blockedActions}/>
          <Metric label="Datos sintéticos"
            value={report.summary.syntheticSnapshots}/>
        </section>
        <section style={card}>
          <h3>CyberScore v2 — persistido, opcional</h3>
          <p>Valor registrado:
            <strong>{" "}{report.summary.v2Score??"No evaluable"}</strong></p>
          <p>Origen del snapshot:
            {report.provenance.latestOptionalV2SourceClass??"ninguno"}</p>
          <p>Este valor no es CyberScore v1, ni acredita
            postura de cliente o cobertura completa.</p>
          <p>Controles/scopes persistidos: {report.summary.controlScopes} ·
            fuentes: {report.summary.sourceFamilies}</p>
        </section>
        <section style={card}>
          <div style={flow}>
            <h3>Resumen por secciones</h3>
            <button style={button}
              onClick={()=>setShowSections(x=>!x)}>
              {showSections?"Contraer":"Mostrar"}
            </button>
          </div>
          {showSections&&sections.map(x=>
            <SectionSummary key={x.id} section={x}/>)}
        </section>
        <section style={card}>
          <h3>Riesgos que requieren atención</h3>
          <ul>{report.risks.filter(x=>x.needsReview).slice(0,8).map(x=>
            <li key={x.riskKey}>{x.severity} · {x.title} ·
              {x.actionState??"Sin acción"}</li>)}</ul>
          {!report.risks.length&&<p>No existen riesgos almacenados
            para mostrar; esto no acredita seguridad verificada.</p>}
        </section>
      </>}
      {(tab==="RISK"||tab==="FOLLOW_UP")&&<>
        <section style={card}>
          <h3>{tab==="RISK"?"Lista de riesgos":
            "Riesgos y sus acciones asociadas"}</h3>
          <div style={flow}>
            <label>Buscar{" "}
              <input value={query}
                onChange={e=>setQuery(e.target.value)}
                placeholder="Control, título, responsable…"/>
            </label>
            <label>Gravedad{" "}
              <select value={severity}
                onChange={e=>setSeverity(e.target.value)}>
                <option value="ALL">Todas</option>
                {["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"]
                  .map(x=><option key={x} value={x}>{x}</option>)}
              </select>
            </label>
            <label>Estado de acción{" "}
              <select value={actionState}
                onChange={e=>setActionState(e.target.value)}>
                <option value="ALL">Todas</option>
                <option value="NONE">Sin acción</option>
                {["OPEN","IN_PROGRESS","BLOCKED","DONE_REPORTED",
                  "EXCEPTION","REOPENED"].map(x=>
                    <option key={x} value={x}>{x}</option>)}
              </select>
            </label>
            <label>Dominio{" "}
              <select value={domain}
                onChange={e=>setDomain(e.target.value)}>
                <option value="ALL">Todos</option>
                {coverage.map(x=><option key={x.domain}
                  value={x.domain}>{x.domain}</option>)}
              </select>
            </label>
            <label>Orden{" "}
              <select value={sort}
                onChange={e=>setSort(e.target.value as typeof sort)}>
                <option value="PRIORITY">Gravedad</option>
                <option value="DUE">Vencimiento</option>
                <option value="NAME">Nombre</option>
              </select>
            </label>
          </div>
          <div style={flow}>
            <label><input type="checkbox" checked={onlyOverdue}
              onChange={e=>setOnlyOverdue(e.target.checked)}/>
              Solo vencidos</label>
            <label><input type="checkbox" checked={onlyWithoutAction}
              onChange={e=>setOnlyWithoutAction(e.target.checked)}/>
              Sin acción asignada</label>
          </div>
          <p>{risks.length} coincidencias.</p>
          <ol>{risks.slice(0,limit).map(x=><RiskRow key={x.riskKey}
            risk={x} open={selected===x.riskKey}
            onClick={()=>setSelected(y=>
              y===x.riskKey?"":x.riskKey)}/>)}</ol>
          {risks.length>limit&&<button style={button}
            onClick={()=>setLimit(v=>v+25)}>Mostrar más</button>}
        </section>
      </>}
      {tab==="COVERAGE"&&<section style={card}>
        <h3>Cobertura observada en registros</h3>
        <p>El porcentaje describe presencia de observaciones en
          la base local, <strong>no</strong> cobertura verificada
          ni ausencia de controles de riesgo.</p>
        <div style={{overflowX:"auto"}}>
          <table>
            <thead><tr>
              <th>Dominio</th><th>Scopes</th><th>Observados</th>
              <th>Declarados</th><th>Inciertos</th>
              <th>Presencia</th>
            </tr></thead>
            <tbody>{coverage.map(x=><CoverageRow key={x.domain}
              item={x}/>)}</tbody>
          </table>
        </div>
        <p>Fuente verificada con total seguridad:
          <strong> NO DETERMINADO</strong>.</p>
      </section>}
      {tab==="FOLLOW_UP"&&<section style={card}>
        <h3>Estado operativo de acciones</h3>
        <div style={flow}>
          <Metric label="Sin responsable"
            value={report.summary.unassignedActions}/>
          <Metric label="Reportadas completadas"
            value={report.summary.reportedCompletedActions}/>
          <Metric label="Excepciones declarativas"
            value={report.summary.declaredExceptions}/>
          <Metric label="Excepciones caducadas"
            value={report.summary.expiredExceptions}/>
        </div>
        <p>Las acciones se actualizan en el Centro de seguimiento,
          no desde este informe inmutable.</p>
      </section>}
      {tab==="AUDIT"&&<section style={card}>
        <h3>Coherencia y procedencia de los registros</h3>
        <p>Consulta íntegra de riesgos:
          {String(report.audit.riskSourceComplete)} ·
          acciones: {String(report.audit.actionsSourceComplete)} ·
          límites tenant: {String(report.audit.riskTenantBound&&
            report.audit.actionTenantBound)}</p>
        <p>Problemas de auditoría:
          {report.summary.auditIssues}</p>
        <label>Buscar incidencia{" "}
          <input value={auditSearch}
            onChange={e=>setAuditSearch(e.target.value)}/>
        </label>
        {qualityIssues.length===0?<p>Sin anomalías adicionales
          entre los registros consultados.</p>:
          <ul>{qualityIssues.map((x,i)=>
            <li key={i+"-"+x}>{x}</li>)}</ul>}
        <button style={button}
          onClick={()=>setShowProvenance(x=>!x)}>
          {showProvenance?"Ocultar":"Ver"} procedencia
        </button>
        {showProvenance&&<div>
          <p>Digest de riesgos:
            <code>{report.provenance.persistedRiskDigest}</code></p>
          <p>Snapshot v2: {report.provenance.latestOptionalV2SnapshotId??
            "No existe"}</p>
          <p>Informe v2 guardado:
            {report.provenance.latestOptionalV2ReportDigest??"No existe"}</p>
          <p>Evaluado: {report.provenance.riskSnapshotTimestamp}</p>
          <p>Proveedor LIVE contactado: <strong>NO</strong></p>
          <p>Tenant autenticado por este informe: <strong>NO</strong></p>
        </div>}
      </section>}
      {tab==="LIMITS"&&<section style={card}>
        <h3>Límites explícitos</h3>
        <button style={button}
          onClick={()=>setShowCaveats(x=>!x)}>
          {showCaveats?"Ocultar":"Mostrar"} detalles
        </button>
        {showCaveats&&<ul>{report.caveats.map(x=>
          <li key={x}>{x}</li>)}</ul>}
        <label><input type="checkbox" checked={includeSources}
          onChange={e=>setIncludeSources(e.target.checked)}/>
          Mostrar fuentes</label>
        {includeSources&&<p>
          Familias de fuentes observadas:
          {report.summary.sourceFamilies} ·
          datos de registro:
          {report.summary.sourceEvidenceCount} ·
          snapshots sintéticos:
          {report.summary.syntheticSnapshots}.
        </p>}
        <p><strong>No existe aceptación legal ni remediación
          externa realizada por este panel.</strong></p>
      </section>}
    </>}
  </div>;
}
