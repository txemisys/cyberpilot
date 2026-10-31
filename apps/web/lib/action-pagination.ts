/**
 * URL and pagination rules for the SME action center.
 * Every query is scoped to one authenticated organization by the caller.
 */
export const ACTION_PAGE_SIZES = [20, 50, 100] as const;
export type ActionPageSize = typeof ACTION_PAGE_SIZES[number];
export type ActionPageInput = {
  page:number;
  pageSize:ActionPageSize;
  search:string;
  severity:"ALL"|"CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO";
  status:"attention"|"active"|"verified"|"all";
};
export type ActionPageResult<T> = {
  items:T[];
  page:number;
  pageSize:number;
  total:number;
  totalPages:number;
  hasPrevious:boolean;
  hasNext:boolean;
  firstItem:number;
  lastItem:number;
};
const severities=["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"] as const;
const statuses=["attention","active","verified","all"] as const;
export function parseActionPageInput(values:Record<string,unknown>):ActionPageInput {
  const requestedSize=Number(values.pageSize);
  const pageSize:ActionPageSize=ACTION_PAGE_SIZES.includes(requestedSize as ActionPageSize)
    ? requestedSize as ActionPageSize:20;
  const requestedPage=typeof values.page==="string"&&/^\d{1,6}$/.test(values.page)
    ? Number(values.page):1;
  const page=Math.min(100000,Math.max(1,requestedPage));
  const rawSearch=typeof values.search==="string"?values.search.trim():"";
  const search=rawSearch.slice(0,120);
  const severity=severities.find(x=>x===values.severity)??"ALL";
  const status=statuses.find(x=>x===values.status)??"attention";
  return {page,pageSize,search,severity,status};
}
export function actionPageResult<T>(items:readonly T[],total:number,settings:ActionPageInput):ActionPageResult<T> {
  const count=Number.isSafeInteger(total)&&total>=0?total:0;
  const totalPages=Math.max(1,Math.ceil(count/settings.pageSize));
  const page=Math.min(settings.page,totalPages);
  const start=(page-1)*settings.pageSize;
  return {
    items:[...items],
    page,pageSize:settings.pageSize,total:count,totalPages,
    hasPrevious:page>1,hasNext:page<totalPages,
    firstItem:count===0?0:start+1,
    lastItem:Math.min(count,start+items.length),
  };
}
export function actionPageUrl(base:string,settings:ActionPageInput,overrides:Partial<ActionPageInput>={}):string {
  const next={...settings,...overrides};
  const query=new URLSearchParams();
  query.set("page",String(next.page));
  query.set("pageSize",String(next.pageSize));
  query.set("status",next.status);
  if(next.search)query.set("search",next.search);
  if(next.severity!=="ALL")query.set("severity",next.severity);
  return base+"?"+query.toString();
}
