"use client";
import { useMemo, useState } from "react";
import type {
  RecoveryFaultMatrix,RecoveryFaultId,
  RecoveryDevelopmentAcceptance,RecoveryFaultMatrixExport,
} from "../lib/offline-recovery-fault-matrix";
type Result={
  organizationId:string;
  archiveSource:"PERSISTED_CAPTURE_ROWS";
  matrix:RecoveryFaultMatrix;
  acceptance:RecoveryDevelopmentAcceptance;
  artifact:RecoveryFaultMatrixExport|null;
  selectedCaptureCount:number;
  faultCount:number;faultDetectionCount:number;
  sqlRestoreOperations:0;providerOperations:0;
  customerLiveValidated:false;productionRecoveryEstablished:false;
  historicalScoreWrites:0;
};
type Envelope={
  data:Result;
  sqlRestoreOperations:0;providerOperations:0;
  customerLiveValidated:false;productionRecoveryEstablished:false;
  historicalScoreWrites:0;
};
const faults:RecoveryFaultId[]=[
  "PAYLOAD_CHECKSUM_TAMPER","REPORT_SOURCE_CHECKSUM_TAMPER",
  "FOREIGN_TENANT_SUBSTITUTION","MISSING_LATEST_CAPTURE",
  "INCOMPLETE_CAPTURE","CAPTURE_OLDER_THAN_POLICY",
  "DUPLICATED_REPORT_KIND","MISMATCHED_REPORT_KIND",
  "CHANGED_EVIDENCE_SOURCE","EMPTY_ARCHIVE",
  "FUTURE_CAPTURE_TIMESTAMP","PAYLOAD_CAPTURE_TIME_TAMPER",
];
const card:React.CSSProperties={
  border:"1px solid #94a3b866",borderRadius:12,padding:18,marginBottom:16,
};
const row:React.CSSProperties={
  display:"flex",alignItems:"center",flexWrap:"wrap",gap:12,
};
const button:React.CSSProperties={
  border:"1px solid #64748b88",background:"transparent",
  color:"inherit",borderRadius:8,padding:"8px 12px",cursor:"pointer",
};
function download(artifact:RecoveryFaultMatrixExport){
  if(!/^[a-z0-9.-]{1,120}$/.test(artifact.filename)||
    !["application/json","text/csv","text/markdown"].includes(artifact.mime))
    throw Error("Archivo de prueba rechazado");
  const url=URL.createObjectURL(new Blob([artifact.content],
    {type:artifact.mime}));
  const link=document.createElement("a");
  link.href=url;link.download=artifact.filename;
  document.body.append(link);link.click();link.remove();
  URL.revokeObjectURL(url);
}
function valid(value:unknown,org:string):value is Envelope{
  if(!value||typeof value!=="object")return false;
  const x=value as Partial<Envelope>;
  return x.sqlRestoreOperations===0&&x.providerOperations===0&&
    x.customerLiveValidated===false&&
    x.productionRecoveryEstablished===false&&
    x.historicalScoreWrites===0&&
    x.data?.organizationId===org&&
    x.data.archiveSource==="PERSISTED_CAPTURE_ROWS"&&
    x.data.sqlRestoreOperations===0&&x.data.providerOperations===0&&
    x.data.customerLiveValidated===false&&
    x.data.productionRecoveryEstablished===false&&
    x.data.historicalScoreWrites===0&&
    x.data.matrix.organizationId===org&&
    x.data.matrix.actualSqlRestoreExecuted===false&&
    x.data.matrix.liveAuthorizationGate==="NOT_VERIFIED"&&
    x.data.matrix.sqlRecoveryGate==="NOT_VERIFIED";
}
export function OfflineRecoveryFaultWorkspace({slug,organizationId}:{
  slug:string;organizationId:string;
}){
  const [selected,setSelected]=useState<RecoveryFaultId[]>([...faults]);
  const [age,setAge]=useState(30);
  const [latest,setLatest]=useState(true);
  const [captureIds,setCaptureIds]=useState("");
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [data,setData]=useState<Result|null>(null);
  const [showOnlyFailed,setShowOnlyFailed]=useState(false);
  const [search,setSearch]=useState("");
  const [details,setDetails]=useState(false);
  const [view,setView]=useState<"MATRIX"|"GATES"|"PROVENANCE">("MATRIX");
  const endpoint="/api/organizations/"+
    encodeURIComponent(slug)+"/offline-recovery-faults";
  const parameters=(format?:string)=>{
    const params=new URLSearchParams();
    params.set("latest",String(latest));
    if(!latest&&captureIds.trim()){
      params.set("ids",captureIds.split(",").map(x=>x.trim()).join(","));
    }
    if(selected.length)params.set("faults",selected.join(","));
    params.set("maxAgeDays",String(age));
    if(format)params.set("format",format);
    return params.toString();
  };
  const read=async(format?:string)=>{
    if(!selected.length)throw Error("Selecciona al menos un fallo");
    if(!latest&&!captureIds.trim())
      throw Error("Indica IDs de capturas para la selección manual");
    const response=await fetch(endpoint+"?"+parameters(format),
      {cache:"no-store"});
    const body:unknown=await response.json();
    if(!response.ok)throw Error((body as {code?:string}).code??
      "No se pudo ejecutar el ensayo");
    if(!valid(body,organizationId))
      throw Error("Respuesta de aceptación incompatible con seguridad");
    return body.data;
  };
  const execute=async(task:()=>Promise<void>)=>{
    if(busy)return;
    setBusy(true);setNotice("");setError("");
    try{await task();}
    catch(cause){setError(cause instanceof Error?cause.message:
      "No se pudo obtener la matriz");}
    finally{setBusy(false);}
  };
  const run=()=>execute(async()=>{
    const result=await read();
    setData(result);
    setNotice("Fallos ejecutados en memoria; cero escrituras SQL.");
  });
  const exportAs=(format:"JSON"|"CSV"|"MARKDOWN")=>execute(async()=>{
    const result=await read(format);
    if(!result.artifact)throw Error("Exportación vacía");
    download(result.artifact);
    setNotice(result.artifact.partial?
      "Expediente parcial exportado; NO apto para certificación.":
      "Expediente de ensayo offline exportado, sin restaurar SQL.");
  });
  const toggle=(fault:RecoveryFaultId)=>{
    setSelected(current=>current.includes(fault)?
      current.filter(x=>x!==fault):[...current,faults.filter(x=>x===fault)[0]!]);
  };
  const displayed=useMemo(()=>(data?.matrix.faults??[]).filter(x=>
    (!showOnlyFailed||!x.detected)&&
    (!search||[x.fault,x.expectedGate,x.detector,x.effect]
      .join(" ").toLowerCase().includes(search.toLowerCase()))),
    [data,showOnlyFailed,search]);
  return <div>
    <section style={card}>
      <h2>Ensayo de fallos y recuperación offline</h2>
      <p>Se alteran exclusivamente clones en memoria de capturas archivadas.
      Ninguna prueba modifica una fila real ni contacta proveedores.
      La restauración PostgreSQL se verifica en un workflow independiente,
      nunca en este navegador.</p>
      <div style={row}>
        <label><input type="checkbox" checked={latest}
          onChange={e=>setLatest(e.target.checked)}/>
          Seleccionar último archivo por tipo</label>
        {!latest&&<label>IDs de capturas (separados por coma){" "}
          <textarea rows={2} value={captureIds}
            onChange={e=>setCaptureIds(e.target.value)}/></label>}
        <label>Edad máxima (días){" "}
          <input type="number" min={1} max={3650} value={age}
            onChange={e=>setAge(Number(e.target.value))}/></label>
      </div>
      <button style={button} onClick={()=>setDetails(x=>!x)}>
        {details?"Ocultar":"Seleccionar"} escenarios de fallo</button>
      {details&&<div style={card}>
        <div style={row}>
          <button style={button} onClick={()=>setSelected([...faults])}>
            Seleccionar todos</button>
          <button style={button} onClick={()=>setSelected([])}>
            Borrar selección</button>
        </div>
        <ul>{faults.map(x=><li key={x}>
          <label><input type="checkbox" checked={selected.includes(x)}
            onChange={()=>toggle(x)}/> {x}</label>
        </li>)}</ul>
      </div>}
      <p>{selected.length} escenarios seleccionados.</p>
      <div style={row}>
        <button style={button} disabled={busy||!selected.length}
          onClick={run}>Ejecutar matriz de fallos</button>
        {(["JSON","CSV","MARKDOWN"] as const).map(x=>
          <button style={button} key={x} disabled={busy||!data}
            onClick={()=>exportAs(x)}>Exportar {x}</button>)}
      </div>
      {busy&&<p role="status">Verificando inyección controlada…</p>}
      {error&&<p role="alert">{error}</p>}
      {notice&&<p role="status">{notice}</p>}
    </section>
    {data&&<>
      <section style={card}>
        <h3>Resultado de integridad offline</h3>
        <div style={row}>
          <span>Capturas: {data.selectedCaptureCount}</span>
          <span>Fallos detectados: {data.faultDetectionCount}/{data.faultCount}</span>
          <span>Estado: <strong>{data.acceptance.status}</strong></span>
        </div>
        <p>Estado previo del archivo: {data.matrix.baselineStatus??"SIN_DATOS"} ·
        huellas originales válidas: {String(data.matrix.sourceCapturesValid)}</p>
        <p>Digest del expediente: <code>{data.matrix.digest}</code></p>
        {data.matrix.undetectedFaults.length>0&&<p role="alert">
          Fallos no detectados: {data.matrix.undetectedFaults.join(", ")}
        </p>}
        <div style={row}>{(["MATRIX","GATES","PROVENANCE"] as const).map(x=>
          <button key={x} style={button} onClick={()=>setView(x)}>{x}</button>)}
        </div>
      </section>
      {view==="MATRIX"&&<section style={card}>
        <h3>Casos de fallo inyectados</h3>
        <div style={row}>
          <label>Filtrar{" "}
            <input value={search} onChange={e=>setSearch(e.target.value)}/></label>
          <label><input type="checkbox" checked={showOnlyFailed}
            onChange={e=>setShowOnlyFailed(e.target.checked)}/>
            Mostrar solo no detectados</label>
        </div>
        <ol>{displayed.map(x=><li key={x.fault} style={{marginBottom:18}}>
          <strong>{x.fault}</strong> · detector {x.detector}
          <p>Gate esperado: {x.expectedGate} ·
            estado observado: {x.actualGateStatus??"No disponible"}</p>
          <p>{x.effect}</p>
          <p>Detectado: <strong>{x.detected?"SÍ":"NO"}</strong> ·
            escenario bloqueado: {String(x.blockedAfter)}</p>
          <p>Filas SQL modificadas: {x.sqlRowsModified} ·
            escrituras proveedor: {x.providerWrites}</p>
        </li>)}</ol>
      </section>}
      {view==="GATES"&&<section style={card}>
        <h3>Expediente de aceptación de desarrollo</h3>
        <ol>{data.acceptance.items.map(x=><li key={x.id}>
          <strong>{x.id} · {x.status}</strong>
          <p>{x.reason}</p>
          <p>Prueba local: {x.evidenceDigest??"No verificada"}</p>
        </li>)}</ol>
        {data.acceptance.actionableProblems.length>0&&<p role="alert">
          Pendientes: {data.acceptance.actionableProblems.join("; ")}
        </p>}
      </section>}
      {view==="PROVENANCE"&&<section style={card}>
        <h3>Separación de las pruebas de recuperación</h3>
        <p>Checksums y linaje JSON: {data.acceptance.jsonRehearsalGate}</p>
        <p>Inyección de fallos: {data.acceptance.faultDetectionGate}</p>
        <p>Restauración SQL real: {data.acceptance.sqlRestoreGate}</p>
        <p>Tenant y proveedor LIVE: {data.acceptance.liveTenantGate}</p>
        <p>Esto no certifica una recuperación de producción,
        ni equivale a autorización del cliente.</p>
        <p>Versiones históricas de CyberScore modificadas: NO.</p>
      </section>}
    </>}
  </div>;
}
