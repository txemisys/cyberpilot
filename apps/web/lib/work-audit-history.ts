/**
 * Stable, tenant-scoped audit history navigation.
 * Cursors are opaque signed-independent tuple data, not authority tokens:
 * every database query still requires organizationId + workItemId.
 */
export class HistoryInputError extends Error{
 constructor(public readonly code:"INVALID"|"NOT_FOUND"|"CAPACITY",message:string){
  super(message);this.name="HistoryInputError";
 }
}
export type HistoryCursor={occurredAt:Date;id:string};
export type HistoryFilter={limit:number;cursor:HistoryCursor|null;kind:string|null;actorUserId:string|null;search:string};
export const HISTORY_KINDS=["CREATED","UPDATED","COMMENTED","REOPENED"] as const;
export type HistoryKind=typeof HISTORY_KINDS[number];
const ID=/^[a-zA-Z0-9_-]{5,100}$/;
export function historyIdentifier(value:unknown):string{
 if(typeof value!=="string"||!ID.test(value))throw new HistoryInputError("INVALID","Invalid history identifier.");
 return value;
}
function positiveLimit(value:unknown):number{
 if(value===undefined||value===null||value==="")return 25;
 if(typeof value!=="string"||!/^\d+$/.test(value))
  throw new HistoryInputError("INVALID","Invalid audit page size.");
 const n=Number(value);
 if(!Number.isSafeInteger(n)||n<1||n>100)
  throw new HistoryInputError("INVALID","History page size must be between 1 and 100.");
 return n;
}
export function encodeHistoryCursor(cursor:HistoryCursor):string{
 if(Number.isNaN(cursor.occurredAt.getTime()))throw new HistoryInputError("INVALID","Invalid cursor timestamp.");
 historyIdentifier(cursor.id);
 return `${cursor.occurredAt.toISOString()}|${cursor.id}`;
}
export function decodeHistoryCursor(value:unknown):HistoryCursor|null{
 if(value===undefined||value===null||value==="")return null;
 if(typeof value!=="string"||value.length>150)
  throw new HistoryInputError("INVALID","Invalid audit cursor.");
 const parts=value.split("|");
 if(parts.length!==2||!parts[0]||!parts[1])
  throw new HistoryInputError("INVALID","Invalid audit cursor.");
 const [date,id]=parts;
 if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(date))
  throw new HistoryInputError("INVALID","Invalid audit cursor timestamp.");
 const at=new Date(date);
 if(Number.isNaN(at.getTime())||at.toISOString()!==date)
  throw new HistoryInputError("INVALID","Noncanonical audit cursor timestamp.");
 return {occurredAt:at,id:historyIdentifier(id)};
}
export function parseHistoryFilter(data:Record<string,unknown>):HistoryFilter{
 const allowed=["limit","cursor","kind","actor","search"];
 if(Object.keys(data).some(key=>!allowed.includes(key)))
  throw new HistoryInputError("INVALID","Unsupported audit filter.");
 const limit=positiveLimit(data.limit);
 const cursor=decodeHistoryCursor(data.cursor);
 const kind=data.kind===undefined||data.kind==="ALL"||data.kind===""?null:data.kind;
 if(kind!==null&&(typeof kind!=="string"||!HISTORY_KINDS.some(x=>x===kind)))
  throw new HistoryInputError("INVALID","Unknown work-event kind.");
 const actorUserId=data.actor===undefined||data.actor===""?null:historyIdentifier(data.actor);
 const search=data.search===undefined?"":data.search;
 if(typeof search!=="string"||search.length>120)
  throw new HistoryInputError("INVALID","Audit search is limited to 120 characters.");
 return {limit,cursor,kind:kind as string|null,actorUserId,search:search.trim()};
}
export function historyOrderWhere(cursor:HistoryCursor|null){
 if(!cursor)return {};
 return {OR:[
  {occurredAt:{lt:cursor.occurredAt}},
  {occurredAt:cursor.occurredAt,id:{lt:cursor.id}}
 ]};
}
export type HistoryRow={id:string;occurredAt:Date;kind:string;actorUserId:string|null;comment:string|null};
export function makeHistoryPage<T extends HistoryRow>(rows:readonly T[],limit:number){
 const hasMore=rows.length>limit;
 const visible=rows.slice(0,limit);
 const last=visible[visible.length-1];
 return {
  rows:visible,hasMore,nextCursor:hasMore&&last?encodeHistoryCursor(last):null,
  returned:visible.length
 };
}
export function histogramHistory(rows:readonly HistoryRow[]){
 const histogram={created:0,updated:0,commented:0,reopened:0,other:0,anonymous:0};
 for(const event of rows){
  if(event.kind==="CREATED")histogram.created++;
  else if(event.kind==="UPDATED")histogram.updated++;
  else if(event.kind==="COMMENTED")histogram.commented++;
  else if(event.kind==="REOPENED")histogram.reopened++;
  else histogram.other++;
  if(!event.actorUserId)histogram.anonymous++;
 }
 return histogram;
}
export function activityDayBuckets(rows:readonly HistoryRow[]){
 const days=new Map<string,number>();
 for(const event of rows){
  const day=event.occurredAt.toISOString().slice(0,10);
  days.set(day,(days.get(day)??0)+1);
 }
 return [...days].map(([date,count])=>({date,count})).sort((a,b)=>a.date.localeCompare(b.date));
}
export function activityByActor(rows:readonly HistoryRow[]){
 const actors=new Map<string,{total:number;comments:number;updates:number}>();
 for(const event of rows){
  const id=event.actorUserId??"DELETED_MEMBER";
  const count=actors.get(id)??{total:0,comments:0,updates:0};
  count.total++;
  if(event.kind==="COMMENTED")count.comments++;
  if(event.kind==="UPDATED"||event.kind==="REOPENED")count.updates++;
  actors.set(id,count);
 }
 return [...actors].map(([actorUserId,summary])=>({actorUserId,...summary}))
  .sort((a,b)=>b.total-a.total||a.actorUserId.localeCompare(b.actorUserId));
}
export function auditExportCell(value:string|number){
 const raw=String(value);
 const neutral=/^[\s\u0000-\u001f]*[=+@\-]/.test(raw)?"'"+raw:raw;
 return '"'+neutral.replaceAll('"','""')+'"';
}
export type AuditExportRow=HistoryRow&{actor:{name:string;email:string}|null;before:unknown;after:unknown};
export const AUDIT_COLUMNS=[
 "Event ID","Timestamp UTC","Event type","Actor ID","Actor name",
 "Actor email","Comment","Before JSON","After JSON"
] as const;
function jsonData(value:unknown):string{
 if(value===null||value===undefined)return "";
 try{return JSON.stringify(value)??"";}catch{return "[UNSERIALIZABLE]";}
}
export function serializeAuditHistory(rows:readonly AuditExportRow[]):string{
 const header=AUDIT_COLUMNS.map(auditExportCell).join(",");
 const entries=rows.map(row=>[
  row.id,row.occurredAt.toISOString(),row.kind,row.actorUserId??"",
  row.actor?.name??"",row.actor?.email??"",row.comment??"",
  jsonData(row.before),jsonData(row.after)
 ].map(auditExportCell).join(","));
 return [header,...entries].join("\r\n")+"\r\n";
}
