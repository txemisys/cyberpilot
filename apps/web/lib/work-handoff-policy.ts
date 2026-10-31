/**
 * Assignment handoffs require an explicit recipient decision.
 * A requested handoff never silently changes ownership of remediation work.
 */
export const HANDOFF_STATES=["REQUESTED","ACCEPTED","DECLINED","CANCELLED"] as const;
export type HandoffState=typeof HANDOFF_STATES[number];
export type HandoffRole="OWNER"|"ADMIN"|"MEMBER"|"AUDITOR";
export type HandoffCommand=
 |{kind:"request";workItemId:string;recipientUserId:string;reason:string;expiresAt:Date|null}
 |{kind:"decide";handoffId:string;revision:number;decision:"ACCEPTED"|"DECLINED";response:string}
 |{kind:"cancel";handoffId:string;revision:number;response:string};
export class HandoffError extends Error{
 constructor(public readonly code:"INVALID"|"FORBIDDEN"|"NOT_FOUND"|"CONFLICT"|"CAPACITY",message:string){
  super(message);this.name="HandoffError";
 }
}
function inputObject(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=="object"||Array.isArray(value))
  throw new HandoffError("INVALID","Expected a JSON object.");
 return value as Record<string,unknown>;
}
function exact(input:Record<string,unknown>,fields:readonly string[]){
 for(const key of Object.keys(input))
  if(!fields.includes(key))throw new HandoffError("INVALID",`Unsupported handoff field: ${key}.`);
}
export function handoffId(value:unknown):string{
 if(typeof value!=="string"||!/^[a-zA-Z0-9_-]{5,100}$/.test(value))
  throw new HandoffError("INVALID","Invalid handoff, work or recipient identifier.");
 return value;
}
export function handoffReason(value:unknown):string{
 if(typeof value!=="string")throw new HandoffError("INVALID","Handoff reason must be text.");
 const reason=value.trim();
 if(reason.length<10||reason.length>2000||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(reason))
  throw new HandoffError("INVALID","Describe the requested work in 10–2000 characters.");
 return reason;
}
export function handoffResponse(value:unknown):string{
 if(typeof value!=="string")throw new HandoffError("INVALID","Response must be text.");
 const response=value.trim();
 if(response.length>2000||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(response))
  throw new HandoffError("INVALID","Response must be no longer than 2000 characters.");
 return response;
}
export function handoffRevision(value:unknown):number{
 if(typeof value!=="number"||!Number.isSafeInteger(value)||value<1||value>2147483647)
  throw new HandoffError("INVALID","Expected a positive revision.");
 return value;
}
export function handoffExpiry(value:unknown,now=new Date()):Date|null{
 if(value===null||value===undefined||value==="")return null;
 if(typeof value!=="string"||!/^\d{4}-\d{2}-\d{2}$/.test(value))
  throw new HandoffError("INVALID","Expiry must be a YYYY-MM-DD date.");
 const date=new Date(value+"T23:59:59.999Z");
 if(Number.isNaN(date.getTime())||date.toISOString().slice(0,10)!==value)
  throw new HandoffError("INVALID","Invalid calendar date.");
 if(date.getTime()<=now.getTime()||date.getTime()>now.getTime()+90*86400000)
  throw new HandoffError("INVALID","Expiry must be within the next 90 days.");
 return date;
}
export function parseHandoffCommand(value:unknown,now=new Date()):HandoffCommand{
 const data=inputObject(value);
 if(data.kind==="request"){
  exact(data,["kind","workItemId","recipientUserId","reason","expiresAt"]);
  return {kind:"request",workItemId:handoffId(data.workItemId),
   recipientUserId:handoffId(data.recipientUserId),
   reason:handoffReason(data.reason),expiresAt:handoffExpiry(data.expiresAt,now)};
 }
 if(data.kind==="decide"){
  exact(data,["kind","handoffId","revision","decision","response"]);
  if(data.decision!=="ACCEPTED"&&data.decision!=="DECLINED")
   throw new HandoffError("INVALID","Decision must accept or decline the request.");
  return {kind:"decide",handoffId:handoffId(data.handoffId),
   revision:handoffRevision(data.revision),decision:data.decision,
   response:handoffResponse(data.response??"")};
 }
 if(data.kind==="cancel"){
  exact(data,["kind","handoffId","revision","response"]);
  return {kind:"cancel",handoffId:handoffId(data.handoffId),
   revision:handoffRevision(data.revision),response:handoffResponse(data.response??"")};
 }
 throw new HandoffError("INVALID","Unknown handoff operation.");
}
export function canRequestHandoff(role:HandoffRole):boolean{
 return role==="OWNER"||role==="ADMIN";
}
export function canDecideHandoff(
 role:HandoffRole,recipientUserId:string,actorUserId:string
):boolean{
 return role!=="AUDITOR"&&recipientUserId===actorUserId;
}
export function canCancelHandoff(
 role:HandoffRole,requesterUserId:string|null,actorUserId:string
):boolean{
 return canRequestHandoff(role)||requesterUserId===actorUserId&&role!=="AUDITOR";
}
export function assertHandoffPermission(
 role:HandoffRole,kind:HandoffCommand["kind"],actorUserId:string,
 requesterUserId:string|null,recipientUserId:string
):void{
 const allowed=kind==="request"?canRequestHandoff(role):
  kind==="decide"?canDecideHandoff(role,recipientUserId,actorUserId):
  canCancelHandoff(role,requesterUserId,actorUserId);
 if(!allowed)throw new HandoffError("FORBIDDEN","Not authorized for this handoff operation.");
}
export type HandoffRecord={
 id:string;workItemId:string;recipientUserId:string;requesterUserId:string|null;
 status:HandoffState;revision:number;expiresAt:Date|null;requestedAt:Date;
};
export function assertPendingHandoff(record:HandoffRecord,revision:number,now=new Date(),allowExpired=false):void{
 if(record.revision!==revision)throw new HandoffError("CONFLICT","Handoff changed; reload.");
 if(record.status!=="REQUESTED")throw new HandoffError("CONFLICT","Handoff already decided.");
 if(!allowExpired&&record.expiresAt&&record.expiresAt.getTime()<now.getTime())
  throw new HandoffError("CONFLICT","Handoff has expired.");
}
export function handoffLabel(record:HandoffRecord,now=new Date()):string{
 if(record.status!=="REQUESTED")return record.status;
 return record.expiresAt&&record.expiresAt<now?"EXPIRED":"AWAITING_RESPONSE";
}
export function handoffSummary(records:readonly HandoffRecord[],now=new Date()){
 const summary={total:records.length,awaiting:0,expired:0,accepted:0,declined:0,cancelled:0};
 for(const item of records){
  const status=handoffLabel(item,now);
  if(status==="AWAITING_RESPONSE")summary.awaiting++;
  if(status==="EXPIRED")summary.expired++;
  if(status==="ACCEPTED")summary.accepted++;
  if(status==="DECLINED")summary.declined++;
  if(status==="CANCELLED")summary.cancelled++;
 }
 return summary;
}
export function handoffTaskWarning(status:string,workStatus:string):string|null{
 if(status==="ACCEPTED"&&workStatus==="DONE")
  return "The accepted assignment does not indicate that the security finding was resolved.";
 if(status==="REQUESTED")
  return "This request has not transferred assignment until the recipient accepts.";
 return null;
}
export function handoffPriority(record:HandoffRecord,now=new Date()):number{
 const label=handoffLabel(record,now);
 if(label==="EXPIRED")return 0;
 if(label==="AWAITING_RESPONSE")return 1;
 if(label==="DECLINED")return 2;
 if(label==="ACCEPTED")return 3;
 return 4;
}
export function orderHandoffs<T extends HandoffRecord>(rows:readonly T[],now=new Date()):T[]{
 return rows.slice().sort((a,b)=>handoffPriority(a,now)-handoffPriority(b,now)||
  a.requestedAt.getTime()-b.requestedAt.getTime()||a.id.localeCompare(b.id));
}
