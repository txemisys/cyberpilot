"use client";
import {useMemo,useState} from "react";
import type{
 EvidenceDecisionReport,EvidenceDecision,EvidenceDecisionCode,
 EvidenceDecisionPriority,EvidenceSourceQuality,EvidenceDomainQuality
}from "../lib/evidence-decision-engine";
type View="PRIORITY"|"DOMAINS"|"SOURCES"|"INTEGRITY"|"EXPORT";
type Response={report:EvidenceDecisionReport;
 plan:{capacity:number;planned:Array<{decisionKey:string;
 estimatedUnits:number;label:string;priority:EvidenceDecisionPriority}>;
 deferred:Array<{decisionKey:string;reason:string}>};
 portfolio:{backlogWithoutEvidence:number;decisions:number};
 providerCalls:0;
 customerCertified:false;historicalScoreWrites:0};
const priorities:EvidenceDecisionPriority[]=["P0","P1","P2","P3"];
const card:React.CSSProperties={border:"1px solid #94a3b866",
 padding:18,borderRadius:12,marginBottom:16};
const flex:React.CSSProperties={display:"flex",gap:12,
 flexWrap:"wrap",alignItems:"center"};
const button:React.CSSProperties={padding:"8px 12px",
 border:"1px solid #64748b88",borderRadius:8,
 background:"transparent",color:"inherit",cursor:"pointer"};
function Metric({title,value,detail}:{
 title:string;value:number|string;detail?:string;
}){return <div style={{...card,flex:"1 1 145px",minWidth:130}}>
 <small>{title}</small><p style={{fontSize:24,fontWeight:700}}>
 {value}</p>{detail&&<small>{detail}</small>}</div>;}
function SourceSummary({source}:{
 source:EvidenceSourceQuality;
}){return <article style={card}>
 <h3>{source.source}</h3>
 <div style={flex}>
 <Metric title="Controles" value={source.totalControls}/>
 <Metric title="Observados con límites" value={source.observedWithLimits}/>
 <Metric title="Declarados" value={source.declared}/>
 <Metric title="Inciertos" value={source.unknown}/>
 <Metric title="Errores" value={source.errors}/>
 <Metric title="Conflictos" value={source.conflicted}/>
 </div>
 <p>Revisiones vinculadas: {source.assignedDecisions} ·
 Evidencias referenciadas: {source.evidenceReferences}</p>
 <p>Autenticación del tenant por este informe: <strong>NO</strong>.</p>
 </article>;}
function DomainSummary({domain,onSelect}:{
 domain:EvidenceDomainQuality;onSelect:()=>void;
}){return <article style={card}>
 <div style={flex}><h3>{domain.domain}</h3>
 <button style={button} onClick={onSelect}>Ver revisiones</button></div>
 <p>Controles: {domain.controls} · hallazgos:
 {domain.findingCount} · abiertos: {domain.unresolvedFindingCount}</p>
 <p>Sin verificación independiente: {domain.unverifiedControls} ·
 obsoletos: {domain.staleControls} · conflictos: {domain.conflicts} ·
 errores: {domain.errors}</p>
 <p>Decisiones: {domain.decisions} · urgentes: {domain.urgentDecisions}</p>
 <p>Verificación de seguridad independiente: no establecida.</p>
 </article>;}
function DecisionDetails({decision,close}:{
 decision:EvidenceDecision;close:()=>void;
}){return <section style={card}>
 <div style={flex}><h3>{decision.code}</h3>
 <button style={button} onClick={close}>Cerrar</button></div>
 <p>{decision.description}</p>
 <p><strong>Acción:</strong> {decision.recommendedAction}</p>
 <p>Prioridad: {decision.priority} ·
 Estado: {decision.status} · plazo orientativo: {decision.dueDays} días</p>
 <p>Dominio: {decision.domain} ·
 Control: {decision.controlId} · scope: {decision.scope}</p>
 <p>Procedencia: {decision.source.join(", ")}</p>
 <p>Antigüedad de la última observación:
 {decision.ageDays===null?"desconocida":decision.ageDays+" días"}</p>
 <p>Confianza: {decision.confidence}</p>
 <h4>Evidencias persistidas</h4>
 {decision.supportingEvidenceIds.length?
 <ul>{decision.supportingEvidenceIds.map(id=>
 <li key={id}><code>{id}</code></li>)}</ul>:
 <p>No hay evidencia identificable vinculada.</p>}
 <h4>Hallazgos originales</h4>
 {decision.supportingFindingIds.length?
 <ul>{decision.supportingFindingIds.map(id=>
 <li key={id}><code>{id}</code></li>)}</ul>:
 <p>Esta revisión es de procedencia o control, no de hallazgo.</p>}
 <p><strong>Cliente certificado por la revisión: NO.</strong></p>
 </section>;}
function download(artifact:{filename:string;mime:string;content:string}){
 if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename))
 throw Error("Archivo no permitido");
 const url=URL.createObjectURL(new Blob([artifact.content],
 {type:artifact.mime}));
 const a=document.createElement("a");a.href=url;
 a.download=artifact.filename;document.body.append(a);a.click();
 a.remove();URL.revokeObjectURL(url);
}
export function EvidenceDecisionWorkspace({slug,organizationId}:{
 slug:string;organizationId:string;
}){
 const [report,setReport]=useState<EvidenceDecisionReport|null>(null);
 const [plan,setPlan]=useState<Response["plan"]|null>(null);
 const [portfolio,setPortfolio]=useState<Response["portfolio"]|null>(null);
 const [busy,setBusy]=useState(false),[error,setError]=useState("");
 const [notice,setNotice]=useState(""),[view,setView]=useState<View>("PRIORITY");
 const [search,setSearch]=useState(""),[source,setSource]=useState("ALL");
 const [domain,setDomain]=useState("ALL"),[code,setCode]=useState("ALL");
 const [priority,setPriority]=useState("ALL");
 const [onlyEvidenceFree,setOnlyEvidenceFree]=useState(false);
 const [showMonitors,setShowMonitors]=useState(false);
 const [selected,setSelected]=useState("");
 const [sort,setSort]=useState<"PRIORITY"|"AGE"|"DOMAIN">("PRIORITY");
 const [limit,setLimit]=useState(30),[integrityQuery,setIntegrityQuery]=useState("");
 const endpoint="/api/organizations/"+encodeURIComponent(slug)+
 "/evidence-decisions";
 const load=async()=>{
 if(busy)return;setBusy(true);setError("");setNotice("");
 try{
 const res=await fetch(endpoint,{cache:"no-store"});
 const body=await res.json() as Partial<Response>;
 if(!res.ok||body.providerCalls!==0||body.customerCertified!==false||
 body.historicalScoreWrites!==0||
 body.report?.organizationId!==organizationId||
 body.report.schema!=="cyberpilot.evidence.decisions.v1"||
 body.report.complianceCertified!==false)
 throw Error("Cola de decisiones no verificable");
 setReport(body.report);
 setPlan(body.plan??null);
 setPortfolio(body.portfolio??null);
 setView("PRIORITY");setSelected("");
 setNotice("Procedencia y decisiones reconciliadas desde PostgreSQL.");
 }catch(cause){
 setError(cause instanceof Error?cause.message:"Consulta fallida");
 setReport(null);
 }finally{setBusy(false);}
 };
 const exportReport=async(format:"JSON"|"CSV"|"MARKDOWN")=>{
 if(!report||busy)return;setBusy(true);setError("");setNotice("");
 try{
 const res=await fetch(endpoint+"?format="+format,{cache:"no-store"});
 const body=await res.json();
 if(!res.ok||body.providerCalls!==0||body.historicalScoreWrites!==0||
 body.customerCertified!==false||!body.artifact)
 throw Error("Exportación denegada");
 download(body.artifact);
 setNotice("Se exportó un nuevo informe de evidencia limitado.");
 }catch(cause){setError(cause instanceof Error?cause.message:"Exportación fallida");}
 finally{setBusy(false);}
 };
 const codes=useMemo(()=>[...new Set((report?.decisions??[]).map(x=>x.code))].sort(),[report]);
 const domains=useMemo(()=>report?.domains.map(x=>x.domain)??[],[report]);
 const sources=useMemo(()=>report?.sources.map(x=>x.source)??[],[report]);
 const selectedDecision=report?.decisions.find(x=>x.key===selected);
 const decisions=useMemo(()=>{
 const needle=search.trim().toLowerCase();
 const filtered=(report?.decisions??[]).filter(x=>
 (priority==="ALL"||priority===x.priority)&&
 (domain==="ALL"||domain===x.domain)&&
 (source==="ALL"||x.source.includes(source as typeof x.source[number]))&&
 (code==="ALL"||code===x.code)&&
 (!onlyEvidenceFree||x.supportingEvidenceIds.length===0)&&
 (showMonitors||x.status!=="MONITOR")&&
 (!needle||[x.description,x.controlId,x.scope,x.recommendedAction,
 x.domain,x.code].join(" ").toLowerCase().includes(needle)));
 return [...filtered].sort((a,b)=>{
 if(sort==="AGE")return(b.ageDays??-1)-(a.ageDays??-1);
 if(sort==="DOMAIN")return a.domain.localeCompare(b.domain);
 return priorities.indexOf(a.priority)-priorities.indexOf(b.priority)||
 a.code.localeCompare(b.code)||a.key.localeCompare(b.key);
 });
 },[report,search,priority,domain,source,code,onlyEvidenceFree,
 showMonitors,sort]);
 return <div>
 <section style={card}>
 <h2>Decisiones para mejorar la calidad de evidencia</h2>
 <p>Esta cola separa evidencias técnicas, declaraciones, errores,
 conflictos, antigüedad y ausencia de scope verificado. Se alimenta
 exclusivamente de registros locales del tenant y no abre
 conexiones LIVE.</p>
 <div style={flex}>
 <button style={button} disabled={busy} onClick={load}>
 Actualizar revisión de evidencias</button>
 <button style={button} disabled={busy||!report}
 onClick={()=>exportReport("JSON")}>Exportar JSON</button>
 <button style={button} disabled={busy||!report}
 onClick={()=>exportReport("CSV")}>Exportar CSV</button>
 <button style={button} disabled={busy||!report}
 onClick={()=>exportReport("MARKDOWN")}>Exportar Markdown</button>
 </div>
 {busy&&<p role="status">Reconciliando fuentes persistidas…</p>}
 {error&&<p role="alert">{error}</p>}
 {notice&&<p role="status">{notice}</p>}
 </section>
 {report&&<>
 <section style={card}>
 <h3>Estado de revisión: {report.outcome}</h3>
 <p>Evaluación: {report.evaluatedAt}</p>
 <p>Integridad: <code style={{overflowWrap:"anywhere"}}>{
 report.reportDigest}</code></p>
 <div style={flex}>
 <Metric title="Revisiones" value={report.totals.decisions}/>
 <Metric title="Urgentes P0" value={report.totals.priority0}/>
 <Metric title="Prioridad P1" value={report.totals.priority1}/>
 <Metric title="Sin evidencia" value={report.totals.decisionsWithoutEvidence}/>
 <Metric title="Conflictos" value={report.totals.conflictingControls}/>
 <Metric title="Registros antiguos" value={report.totals.staleControls}/>
 </div>
 <div style={flex}>
 {(["PRIORITY","DOMAINS","SOURCES","INTEGRITY","EXPORT"] as View[]).map(x=>
 <button key={x} style={{...button,fontWeight:view===x?700:400}}
 onClick={()=>setView(x)}>{x}</button>)}
 </div>
 </section>
 {view==="PRIORITY"&&<section style={card}>
 <h3>Cola de revisión por prioridad</h3>
 <div style={flex}>
 <label>Buscar{" "}<input value={search}
 onChange={e=>{setSearch(e.target.value);setLimit(30);}}/></label>
 <label>Prioridad{" "}<select value={priority}
 onChange={e=>setPriority(e.target.value)}>
 <option value="ALL">Todas</option>
 {priorities.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Dominio{" "}<select value={domain}
 onChange={e=>setDomain(e.target.value)}>
 <option value="ALL">Todos</option>
 {domains.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Fuente{" "}<select value={source}
 onChange={e=>setSource(e.target.value)}>
 <option value="ALL">Todas</option>
 {sources.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Motivo{" "}<select value={code}
 onChange={e=>setCode(e.target.value)}>
 <option value="ALL">Todos</option>
 {codes.map(x=><option key={x} value={x}>{x}</option>)}
 </select></label>
 <label>Orden{" "}<select value={sort}
 onChange={e=>setSort(e.target.value as typeof sort)}>
 <option value="PRIORITY">Prioridad</option>
 <option value="AGE">Antigüedad</option>
 <option value="DOMAIN">Dominio</option>
 </select></label>
 </div>
 <div style={flex}>
 <label><input type="checkbox" checked={onlyEvidenceFree}
 onChange={e=>setOnlyEvidenceFree(e.target.checked)}/>
 Solo sin evidencia vinculada</label>
 <label><input type="checkbox" checked={showMonitors}
 onChange={e=>setShowMonitors(e.target.checked)}/>
 Incluir monitorización</label>
 </div>
 <p>{decisions.length} revisiones. El plazo indicado
 es orientativo para triage, no una obligación legal.</p>
 <ol>{decisions.slice(0,limit).map(x=><li key={x.key}
 style={{marginBottom:14}}>
 <button style={button} onClick={()=>setSelected(x.key)}>
 <strong>{x.priority}</strong> · {x.code} · {x.controlId}</button>
 <p>{x.domain} · {x.status} · {x.source.join(", ")}</p>
 </li>)}</ol>
 {decisions.length>limit&&<button style={button}
 onClick={()=>setLimit(x=>x+30)}>Mostrar más</button>}
 {selectedDecision&&<DecisionDetails decision={selectedDecision}
 close={()=>setSelected("")}/>}
 </section>}
 {view==="DOMAINS"&&<section style={card}>
 <h3>Calidad por dominio</h3>
 {report.domains.map(x=><DomainSummary key={x.domain}
 domain={x} onSelect={()=>{setDomain(x.domain);setView("PRIORITY");}}/>)}
 {report.domains.length===0&&<p>No hay dominios observados;
 eso no implica cobertura completa.</p>}
 </section>}
 {view==="SOURCES"&&<section style={card}>
 <h3>Estado de fuentes</h3>
 {report.sources.map(x=><SourceSummary key={x.source} source={x}/>)}
 {report.sources.length===0&&<p>No hay fuentes persistidas.
 Un registro vacío no acredita seguridad.</p>}
 </section>}
 {view==="INTEGRITY"&&<section style={card}>
 <h3>Calidad de procedencia</h3>
 <p>Integridad local del informe: SHA-256 de datos canónicos.
 No equivale a firma de un cliente o de su proveedor.</p>
 <p>Digest del registro original: <code style={{overflowWrap:"anywhere"}}>
 {report.riskDigest}</code></p>
 <label>Buscar incidencia{" "}
 <input value={integrityQuery}
 onChange={e=>setIntegrityQuery(e.target.value)}/></label>
 {report.qualityIssues.filter(x=>x.toLowerCase().includes(
 integrityQuery.toLowerCase())).map(x=><p key={x}>{x}</p>)}
 <p>Resolución automática de hallazgos: NO.</p>
 <p>Autenticación LIVE de tenant: NO.</p>
 <p>Certificación de cumplimiento: NO.</p>
 </section>}
 {view==="EXPORT"&&<section style={card}>
 <h3>Alcance del expediente</h3>
 {portfolio&&<p>Inventario de decisiones: {portfolio.decisions} ·
 decisiones sin evidencia referenciada:
 {portfolio.backlogWithoutEvidence}. La ausencia de referencias no
 equivale a un control aprobado.</p>
 {plan&&<section style={card}>
 <h4>Plan de revisión de catorce días (propuesta)</h4>
 <p>Capacidad máxima: {plan.capacity} unidades;
 seleccionadas: {plan.planned.length};
 diferidas: {plan.deferred.length}.</p>
 <ol>{plan.planned.map(x=><li key={x.decisionKey}>
 {x.priority} · {x.label} · {x.estimatedUnits} unidades
 </li>)}</ol>
 <p>El plan no realiza ninguna acción ni asigna responsables reales.</p>
 </section>}
 <p>Incluye priorización operativa, referencias originales y
 descripción de la incertidumbre. No contiene llamadas
 a proveedores o secretos OAuth.</p>
 <p>Conserva referencias de evidencias y hallazgos para que
 cada revisión pueda reproducirse desde los registros.</p>
 <p>Decisiones sin evidencia: {report.totals.decisionsWithoutEvidence}.</p>
 <p>Revisiones que requieren prueba técnica:
 {report.totals.needsTechnicalProof}.</p>
 <p>Revisiones que requieren prueba de scope:
 {report.totals.needsScopeProof}.</p>
 <p><strong>No emitir conclusiones de seguridad sobre controles UNKNOWN.</strong></p>
 </section>}
 </>}
 </div>;
}
