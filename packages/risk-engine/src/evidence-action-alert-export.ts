import type { ActionAlertDigest } from "./evidence-action-alert-digest";
/** Read-only, tenant-verified export of offline alert suggestions. */
export type ActionAlertExport = { ok:true; format:"csv"|"json"; filename:string; content:string } | {ok:false;error:"TENANT_MISMATCH"|"INVALID_DIGEST"};
const codes=["OVERDUE","DUE_SOON","BLOCKED","HIGH_PRIORITY_OPEN"] as const;
const priorities=["HIGH","MEDIUM","LOW"] as const;
const csv=(value:string)=>'"'+(/^[\s]*[=+@\-]/.test(value)?"'"+value:value).replace(/"/g,'""')+'"';
export function exportActionAlertDigest(digest:ActionAlertDigest,organizationId:string,format:"csv"|"json"):ActionAlertExport {
 if(!organizationId||organizationId!==digest.organizationId)return {ok:false,error:"TENANT_MISMATCH"};
 const items=digest.items;
 if(digest.total!==items.length||new Set(items.map(x=>JSON.stringify([x.actionId,x.code]))).size!==items.length||
 items.some(x=>!x.actionId.trim()||!codes.includes(x.code)||!priorities.includes(x.priority))||
 digest.high!==items.filter(x=>x.priority==="HIGH").length||
 digest.medium!==items.filter(x=>x.priority==="MEDIUM").length||
 digest.low!==items.filter(x=>x.priority==="LOW").length||
 codes.some(code=>digest.byCode[code]!==items.filter(x=>x.code===code).length))return {ok:false,error:"INVALID_DIGEST"};
 if(format==="json")return {ok:true,format,filename:"action-alerts.json",content:JSON.stringify({schemaVersion:1,organizationId,items,summary:{total:digest.total,high:digest.high,medium:digest.medium,low:digest.low,byCode:digest.byCode}})};
 return {ok:true,format,filename:"action-alerts.csv",content:["actionId,code,priority",...items.map(x=>[x.actionId,x.code,x.priority].map(csv).join(","))].join("\r\n")+"\r\n"};
}
