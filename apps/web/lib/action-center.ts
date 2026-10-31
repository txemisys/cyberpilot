export type ActionCenterView = "attention" | "active" | "verified" | "all";
export const ACTION_CENTER_VIEWS: readonly ActionCenterView[] = ["attention","active","verified","all"];

export type ActionCenterRecord = {
  id:string;
  status:string;
  needsVerification:boolean;
  title:string;
  findingStatus:string;
  severity:string;
};

export function parseActionCenterView(value:unknown):ActionCenterView {
  return ACTION_CENTER_VIEWS.find(view=>view===value)??"attention";
}

/** Status filtering cannot imply that a proposed or acknowledged action is verified. */
export function filterActionCenterRecords<T extends ActionCenterRecord>(
  actions:readonly T[], view:ActionCenterView,
):T[] {
  return actions.filter(action=>{
    if(view==="all")return true;
    if(view==="verified")return action.status==="VERIFIED";
    if(view==="active")return action.status==="EXECUTING";
    return action.needsVerification||["FAILED","PROPOSED","APPROVED"].includes(action.status);
  });
}

export function summarizeActionCenterRecords(actions:readonly ActionCenterRecord[]) {
  return {
    total:actions.length,
    inProgress:actions.filter(x=>x.status==="EXECUTING").length,
    needsVerification:actions.filter(x=>x.needsVerification).length,
    verified:actions.filter(x=>x.status==="VERIFIED").length,
    needsAttention:filterActionCenterRecords(actions,"attention").length,
  };
}

const csvCell=(value:string)=>{
  const safe=/^[=+@\-\t\r\n]/.test(value)?"'"+value:value;
  return '"'+safe.replaceAll('"','""')+'"';
};

/** Export only the tenant-scoped records supplied by the authorized reader. */
export function exportActionCenterCsv(actions:readonly ActionCenterRecord[],organizationId:string):string|null {
  if(!organizationId||actions.some(x=>!x.id||!x.title||!x.severity))return null;
  const header=["actionId","title","status","severity","findingStatus","needsVerification"];
  return "\uFEFF"+[header.join(","),...actions.map(action=>[
    action.id,action.title,action.status,action.severity,action.findingStatus,
    action.needsVerification?"YES":"NO",
  ].map(csvCell).join(","))].join("\r\n")+"\r\n";
}

export type ActionCenterQuery = { search:string; severity:string };
export const ACTION_CENTER_SEVERITIES = ["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"] as const;
/** Normalize untrusted URL inputs before using them in filters or export requests. */
export function parseActionCenterQuery(search:unknown,severity:unknown):ActionCenterQuery {
  const raw=typeof search==="string"?search.trim().slice(0,120):"";
  const selected=typeof severity==="string"?severity.toUpperCase():"ALL";
  return {search:raw,severity:ACTION_CENTER_SEVERITIES.includes(selected as typeof ACTION_CENTER_SEVERITIES[number])?selected:"ALL"};
}
export function searchActionCenterRecords<T extends ActionCenterRecord>(
 actions:readonly T[],query:ActionCenterQuery,
):T[] {
 const search=query.search.toLocaleLowerCase();
 return actions.filter(item=>
   (query.severity==="ALL"||item.severity===query.severity) &&
   (!search||[item.title,item.id,item.status,item.severity,item.findingStatus]
     .some(value=>value.toLocaleLowerCase().includes(search)))
 );
}
