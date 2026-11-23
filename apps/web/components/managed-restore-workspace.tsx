"use client";
import { useEffect, useState } from "react";
import type { RecoverySession, RecoveryPolicy, RecoveryTier,
  RecoveryEnvironment, RecoveryObservation, RecoveryStage,
  RecoveryEvidenceSource } from "../lib/managed-recovery-objectives";
const tiers:RecoveryTier[]=["STANDARD","BUSINESS","CRITICAL"];
const environments:RecoveryEnvironment[]=[
  "CI_SYNTHETIC","LOCAL_LAB","MANAGED_STAGING","PRODUCTION"];
const stages:RecoveryStage[]=[
  "BACKUP_IDENTIFIED","RESTORE_STARTED","RESTORE_FINISHED",
  "SCHEMA_VERIFIED","APP_STARTED","DATA_VERIFIED","ACCESS_REVIEWED",
  "CLEANUP_CONFIRMED"];
const sources:RecoveryEvidenceSource[]=[
  "CI_RUN","DATABASE_QUERY","BACKUP_PROVIDER","APPLICATION_HEALTH",
  "OPERATOR_NOTE","ACCESS_CONTROL_REVIEW","EXTERNAL_ATTESTATION"];
type Result={dossier:{status:string;gaps:Array<{code:string;recommendedAction:string}>;
  assessment:{rpo:{status:string;observedMinutes:number|null};
    rto:{status:string;observedMinutes:number|null};
    gates:Array<{id:string;status:string;reason:string}>}};
  faults:{detectedCount:number;scenarioCount:number;undetected:string[]}|null;
  artifact:{content:string;filename:string}|null};
export function ManagedRestoreWorkspace({slug,userId,mayExport}:{
  slug:string;userId:string;mayExport:boolean;
}){
  const endpoint="/api/organizations/"+encodeURIComponent(slug)+"/managed-restore";
  const [policy,setPolicy]=useState<RecoveryPolicy|null>(null);
  const [tier,setTier]=useState<RecoveryTier>("STANDARD");
  const [environment,setEnvironment]=useState<RecoveryEnvironment>("LOCAL_LAB");
  const [sourceName,setSourceName]=useState("");
  const [targetName,setTargetName]=useState("");
  const [backupAt,setBackupAt]=useState("");
  const [incidentAt,setIncidentAt]=useState("");
  const [startedAt,setStartedAt]=useState("");
  const [finishedAt,setFinishedAt]=useState("");
  const [usableAt,setUsableAt]=useState("");
  const [isolated,setIsolated]=useState<"UNKNOWN"|"YES"|"NO">("UNKNOWN");
  const [stage,setStage]=useState<RecoveryStage>("BACKUP_IDENTIFIED");
  const [evidenceSource,setEvidenceSource]=useState<RecoveryEvidenceSource>("OPERATOR_NOTE");
  const [evidenceRef,setEvidenceRef]=useState("");
  const [evidenceNote,setEvidenceNote]=useState("");
  const [observations,setObservations]=useState<RecoveryObservation[]>([]);
  const [result,setResult]=useState<Result|null>(null);
  const [artifact,setArtifact]=useState("");
  const [message,setMessage]=useState("");
  const [busy,setBusy]=useState(false);
  const [runbook,setRunbook]=useState<Record<string,unknown>|null>(null);
  const toIso=(value:string):string|null=>{
    if(!value)return null;
    const date=new Date(value);
    return Number.isFinite(date.getTime())?date.toISOString():null;
  };
  async function loadPolicy(){
    const q=new URLSearchParams({tier,environment});
    const response=await fetch(endpoint+"?"+q,{cache:"no-store"});
    const data=await response.json();
    if(!response.ok)throw Error(data.code??"RESTORE_POLICY_UNAVAILABLE");
    setPolicy(data.data.policy as RecoveryPolicy);
    setRunbook(data.data.runbook as Record<string,unknown>);
  }
  useEffect(()=>{void loadPolicy().catch(e=>setMessage(String(e)));},[
    endpoint,tier,environment]);
  function addObservation(){
    if(!evidenceRef.trim()||!evidenceNote.trim())return;
    const now=new Date().toISOString();
    const entry:RecoveryObservation={
      id:crypto.randomUUID(),stage,source:evidenceSource,
      sourceReference:evidenceRef,recordedById:userId,recordedAt:now,
      observedAt:now,signal:"DECLARED",evidenceDigest:null,
      independent:false,verifierId:null,note:evidenceNote,
    };
    setObservations(old=>[...old,entry].slice(-120));
    setEvidenceNote("");setEvidenceRef("");
    setMessage("Declaración añadida. No constituye verificación independiente.");
  }
  async function analyze(format?:"JSON"|"CSV"|"MARKDOWN",faults=false){
    if(!policy)return;
    setBusy(true);setMessage("");
    try{
      const now=new Date().toISOString();
      const session:RecoverySession={
        schema:"cyberpilot.managed.restore.session.v1",
        id:crypto.randomUUID(),organizationId:"",
        tier,environment,policy,sourceName,targetName,
        initiatedById:userId,evaluatorId:null,initiatedAt:now,asOf:now,
        incidentStartedAt:toIso(incidentAt),
        latestRestorableBackupAt:toIso(backupAt),
        backupCreatedAt:toIso(backupAt),
        restoreStartedAt:toIso(startedAt),
        restoreFinishedAt:toIso(finishedAt),
        applicationUsableAt:toIso(usableAt),
        originalSourceRetained:true,
        targetIsolated:isolated==="UNKNOWN"?null:isolated==="YES",
        verifiedReadOnly:false,observations,
        operatorApprovalRef:null,
        actualExternalRestorePerformedByCyberPilot:false,
        customerTenantCredentialsUsed:false,
      };
      // Server is authority for the organization ID. The client only
      // names its current organization via this route, not provider tenants.
      const me=await fetch("/api/organizations/"+encodeURIComponent(slug)+
        "/offline-jobs?limit=1",{cache:"no-store"});
      if(!me.ok)throw Error("ORGANIZATION_SCOPE_UNAVAILABLE");
      const active=await me.json();
      const organizationId=active.data?.organizationId;
      if(typeof organizationId!=="string")throw Error("ORGANIZATION_ID_UNAVAILABLE");
      session.organizationId=organizationId;
      const response=await fetch(endpoint,{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({session,...(format?{format}:{}),faults}),
      });
      const data=await response.json();
      if(!response.ok)throw Error(data.code??"RESTORE_ASSESSMENT_FAILED");
      setResult(data.data as Result);
      setArtifact(data.data.artifact?.content??"");
      setMessage("Evaluación local realizada; no se han restaurado bases de datos.");
    }catch(e){setMessage(String(e));}finally{setBusy(false);}
  }
  return <section aria-label="Objetivos de recuperación">
    <p role="note">La información introducida es declarada por un operador:
      nunca se convierte en una prueba independiente de restauración.
      No se ejecutan comandos contra la base de datos ni contra proveedores.</p>
    <h2>Definir alcance</h2>
    <label>Tier <select value={tier} onChange={e=>
      setTier(e.target.value as RecoveryTier)}>
      {tiers.map(x=><option key={x} value={x}>{x}</option>)}</select></label>
    <label>Entorno <select value={environment} onChange={e=>
      setEnvironment(e.target.value as RecoveryEnvironment)}>
      {environments.map(x=><option key={x} value={x}>{x}</option>)}</select></label>
    {policy&&<p>Objetivo RPO: {policy.rpoMinutes} minutos.
      Objetivo RTO: {policy.rtoMinutes} minutos.
      Retención: {policy.backupRetentionDays} días.</p>}
    <label>Fuente de copia <input value={sourceName}
      onChange={e=>setSourceName(e.target.value)} maxLength={120}/></label>
    <label>Destino aislado <input value={targetName}
      onChange={e=>setTargetName(e.target.value)} maxLength={120}/></label>
    <label>Aislamiento verificado por operador
      <select value={isolated} onChange={e=>
        setIsolated(e.target.value as "UNKNOWN"|"YES"|"NO")}>
        <option value="UNKNOWN">No confirmado</option>
        <option value="YES">Declarado aislado</option>
        <option value="NO">No aislado</option>
      </select></label>
    <h3>Marcas de tiempo (UTC tras conversión)</h3>
    {([
      ["Backup disponible",backupAt,setBackupAt],
      ["Inicio del incidente",incidentAt,setIncidentAt],
      ["Inicio de la restauración",startedAt,setStartedAt],
      ["Fin de la restauración",finishedAt,setFinishedAt],
      ["Aplicación utilizable",usableAt,setUsableAt],
    ] as const).map(([label,value,change])=>
      <label key={label}>{label}<input type="datetime-local"
        value={value} onChange={e=>change(e.target.value)}/></label>)}
    <h3>Evidencia declarada, sin certificación</h3>
    <label>Etapa <select value={stage} onChange={e=>
      setStage(e.target.value as RecoveryStage)}>
      {stages.map(x=><option key={x} value={x}>{x}</option>)}</select></label>
    <label>Origen <select value={evidenceSource} onChange={e=>
      setEvidenceSource(e.target.value as RecoveryEvidenceSource)}>
      {sources.map(x=><option key={x} value={x}>{x}</option>)}</select></label>
    <label>Referencia <input maxLength={255} value={evidenceRef}
      onChange={e=>setEvidenceRef(e.target.value)}/></label>
    <label>Descripción breve <input maxLength={1200} value={evidenceNote}
      onChange={e=>setEvidenceNote(e.target.value)}/></label>
    <button type="button" disabled={busy||observations.length>=120}
      onClick={addObservation}>Anotar evidencia no verificada</button>
    <p>Declaraciones de operador: {observations.length}.</p>
    <button type="button" disabled={busy||!policy||!sourceName||!targetName}
      onClick={()=>void analyze()}>Evaluar RPO/RTO sin restaurar</button>
    <button type="button" disabled={busy||!policy||!sourceName||!targetName}
      onClick={()=>void analyze(undefined,true)}>Simular 16 fallos en memoria</button>
    {mayExport&&(["JSON","CSV","MARKDOWN"] as const).map(f=>
      <button key={f} type="button" disabled={busy||!policy||!sourceName||!targetName}
        onClick={()=>void analyze(f)}>Preparar expediente {f}</button>)}
    {result&&<section aria-label="Evaluación de restauración">
      <h3>Resultado: {result.dossier.status}</h3>
      <p>RPO: {result.dossier.assessment.rpo.status}.
        RTO: {result.dossier.assessment.rto.status}.</p>
      <p>Restauración real verificada: NO.</p>
      <ul>{result.dossier.assessment.gates.map(g=><li key={g.id}>
        {g.id}: {g.status} — {g.reason}
      </li>)}</ul>
      {result.faults&&<p>Fallos detectados en simulación:
        {result.faults.detectedCount}/{result.faults.scenarioCount}.
        Sin restauración SQL.</p>}
      {artifact&&<textarea aria-label="Expediente de recuperación"
        value={artifact} readOnly rows={12}/>}
    </section>}
    {runbook&&<details><summary>Procedimiento de recuperación sin ejecutar</summary>
      <pre>{JSON.stringify(runbook,null,2)}</pre></details>}
    <p role="status">{message}</p>
  </section>;
}
