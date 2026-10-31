import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import {
  canCommentWork,canManageWork,deriveWorkDue,parseWorkFilter,parseWorkMutation,
  transitionWorkStatus,WorkInputError,type WorkFilter,type WorkRole
} from "./remediation-work-input";

export type WorkContext={organizationId:string;userId:string;role:WorkRole};
export type WorkView=Awaited<ReturnType<typeof listWorkItems>>;
const itemSelect={
  id:true,organizationId:true,remediationId:true,findingId:true,
  title:true,description:true,status:true,priority:true,
  assigneeUserId:true,dueAt:true,completedAt:true,revision:true,
  createdAt:true,updatedAt:true,
  remediation:{select:{title:true,status:true,mode:true}},
  finding:{select:{title:true,severity:true,status:true}},
  assignee:{select:{id:true,name:true,email:true}},
} as const;
const historySelect={
  id:true,kind:true,actorUserId:true,comment:true,before:true,after:true,occurredAt:true,
  actor:{select:{name:true,email:true}},
} as const;

function assertPermission(context:WorkContext, action:"read"|"write"|"comment"):void {
  if(action==="write"&&!canManageWork(context.role))
    throw new WorkInputError("FORBIDDEN","Only organization owners and admins can manage work items.");
  if(action==="comment"&&!canCommentWork(context.role))
    throw new WorkInputError("FORBIDDEN","Auditors can review work but cannot comment.");
}
async function assertAssignee(
  tx:Prisma.TransactionClient,organizationId:string,userId:string|null
):Promise<void>{
  if(!userId)return;
  const match=await tx.membership.findFirst({
    where:{organizationId,userId},
    select:{userId:true},
  });
  if(!match)throw new WorkInputError("INVALID","Assignee must be a member of this organization.");
}
function snapshot(work:{
  title:string;description:string;status:string;priority:string;
  assigneeUserId:string|null;dueAt:Date|null;completedAt:Date|null;revision:number;
}){
  return {
    title:work.title,description:work.description,status:work.status,priority:work.priority,
    assigneeUserId:work.assigneeUserId,dueAt:work.dueAt?.toISOString()??null,
    completedAt:work.completedAt?.toISOString()??null,revision:work.revision
  };
}
export function workWhere(organizationId:string,filter:WorkFilter,now:Date):Prisma.RemediationWorkItemWhereInput{
  const where:Prisma.RemediationWorkItemWhereInput={organizationId};
  if(filter.status!=="ALL")where.status=filter.status;
  if(filter.priority!=="ALL")where.priority=filter.priority;
  if(filter.assigneeUserId==="UNASSIGNED")where.assigneeUserId=null;
  else if(filter.assigneeUserId!=="ALL")where.assigneeUserId=filter.assigneeUserId;
  if(filter.search)where.OR=[
    {title:{contains:filter.search,mode:"insensitive"}},
    {description:{contains:filter.search,mode:"insensitive"}},
    {remediation:{title:{contains:filter.search,mode:"insensitive"}}},
    {finding:{title:{contains:filter.search,mode:"insensitive"}}}
  ];
  if(filter.due==="NO_DATE")where.dueAt=null;
  if(filter.due==="OVERDUE"){
    where.dueAt={lt:now};
    where.status={notIn:["DONE","CANCELLED"]};
  }
  if(filter.due==="NEXT_7_DAYS"){
    where.dueAt={gte:now,lte:new Date(now.getTime()+7*86400000)};
    where.status={notIn:["DONE","CANCELLED"]};
  }
  return where;
}
export async function listWorkItems(
  context:WorkContext,query:Record<string,unknown>,now=new Date()
){
  assertPermission(context,"read");
  const filter=parseWorkFilter(query);
  const where=workWhere(context.organizationId,filter,now);
  const [total,rows]=await db.$transaction([
    db.remediationWorkItem.count({where}),
    db.remediationWorkItem.findMany({
      where,select:itemSelect,
      orderBy:[{updatedAt:"desc"},{id:"asc"}],
      skip:(filter.page-1)*filter.pageSize,take:filter.pageSize
    })
  ]);
  return {
    filter,total,page:filter.page,pageSize:filter.pageSize,
    pages:Math.max(1,Math.ceil(total/filter.pageSize)),
    rows:rows.map(row=>({...row,dueState:deriveWorkDue(now,row.dueAt,row.status)})),
    coverage:"Pagination applies only to matching work items; it does not assess security evidence."
  };
}
export async function getWorkItem(context:WorkContext,id:string){
  assertPermission(context,"read");
  const item=await db.remediationWorkItem.findFirst({
    where:{id,organizationId:context.organizationId},
    select:{...itemSelect,events:{
      where:{organizationId:context.organizationId},
      orderBy:[{occurredAt:"desc"},{id:"desc"}],
      take:100,select:historySelect
    }}
  });
  if(!item)throw new WorkInputError("MISSING","Work item not found.");
  const count=await db.remediationWorkEvent.count({
    where:{organizationId:context.organizationId,workItemId:id}
  });
  return {...item,historyTruncated:count>item.events.length,totalEvents:count};
}
export async function organizationAssignees(context:WorkContext){
  assertPermission(context,"read");
  return db.membership.findMany({
    where:{organizationId:context.organizationId},
    select:{role:true,user:{select:{id:true,name:true,email:true}}},
    orderBy:{user:{name:"asc"}},take:500
  });
}
export async function createWorkItem(context:WorkContext,input:unknown){
  assertPermission(context,"write");
  const mutation=parseWorkMutation({kind:"create",value:input});
  if(mutation.kind!=="create")throw new WorkInputError("INVALID","Invalid create operation.");
  const value=mutation.value;
  return db.$transaction(async tx=>{
    const remediation=await tx.remediation.findFirst({
      where:{id:value.remediationId,organizationId:context.organizationId},
      select:{id:true,findingId:true,title:true}
    });
    if(!remediation)throw new WorkInputError("MISSING","Remediation does not exist in this organization.");
    const exists=await tx.remediationWorkItem.findFirst({
      where:{organizationId:context.organizationId,remediationId:value.remediationId},select:{id:true}
    });
    if(exists)throw new WorkInputError("CONFLICT","This remediation already has a work item.");
    await assertAssignee(tx,context.organizationId,value.assigneeUserId);
    const work=await tx.remediationWorkItem.create({
      data:{
        organizationId:context.organizationId,remediationId:remediation.id,
        findingId:remediation.findingId,title:value.title,description:value.description,
        status:value.status,priority:value.priority,assigneeUserId:value.assigneeUserId,
        dueAt:value.dueAt,completedAt:value.status==="DONE"?new Date():null
      }
    });
    await tx.remediationWorkEvent.create({
      data:{
        organizationId:context.organizationId,workItemId:work.id,actorUserId:context.userId,
        kind:"CREATED",after:snapshot(work)
      }
    });
    return work;
  },{isolationLevel:"Serializable"});
}
export async function updateWorkItem(
  context:WorkContext,id:string,revision:number,input:unknown
){
  assertPermission(context,"write");
  const mutation=parseWorkMutation({kind:"update",id,revision,value:input});
  if(mutation.kind!=="update")throw new WorkInputError("INVALID","Invalid update operation.");
  return db.$transaction(async tx=>{
    const previous=await tx.remediationWorkItem.findFirst({
      where:{id,organizationId:context.organizationId}
    });
    if(!previous)throw new WorkInputError("MISSING","Work item not found.");
    if(previous.revision!==revision)
      throw new WorkInputError("CONFLICT","The work item changed. Reload before editing.");
    const patch=mutation.value;
    if("assigneeUserId" in patch)await assertAssignee(tx,context.organizationId,patch.assigneeUserId??null);
    const nextStatus=patch.status??previous.status;
    const transition=transitionWorkStatus(previous.status,nextStatus);
    const now=new Date();
    const completedAt=nextStatus==="DONE"
      ? previous.status==="DONE"?previous.completedAt??now:now
      :null;
    const changed=await tx.remediationWorkItem.updateMany({
      where:{id,organizationId:context.organizationId,revision},
      data:{...patch,completedAt,revision:{increment:1}}
    });
    if(changed.count!==1)throw new WorkInputError("CONFLICT","Concurrent change detected.");
    const next=await tx.remediationWorkItem.findFirstOrThrow({
      where:{id,organizationId:context.organizationId}
    });
    await tx.remediationWorkEvent.create({
      data:{
        organizationId:context.organizationId,workItemId:id,actorUserId:context.userId,
        kind:transition==="REOPEN"?"REOPENED":"UPDATED",
        before:snapshot(previous),after:snapshot(next)
      }
    });
    return next;
  },{isolationLevel:"Serializable"});
}
export async function commentWorkItem(context:WorkContext,id:string,comment:unknown){
  assertPermission(context,"comment");
  const mutation=parseWorkMutation({kind:"comment",id,comment});
  if(mutation.kind!=="comment")throw new WorkInputError("INVALID","Invalid comment operation.");
  return db.$transaction(async tx=>{
    const item=await tx.remediationWorkItem.findFirst({
      where:{id,organizationId:context.organizationId},
      select:{id:true}
    });
    if(!item)throw new WorkInputError("MISSING","Work item not found.");
    return tx.remediationWorkEvent.create({
      data:{
        organizationId:context.organizationId,workItemId:id,actorUserId:context.userId,
        kind:"COMMENTED",comment:mutation.comment
      }
    });
  });
}
export async function workSummaryForOrganization(context:WorkContext,now=new Date()){
  assertPermission(context,"read");
  const [all,open,blocked,done,overdue,unassigned]=await db.$transaction([
    db.remediationWorkItem.count({where:{organizationId:context.organizationId}}),
    db.remediationWorkItem.count({where:{organizationId:context.organizationId,status:{in:["TODO","IN_PROGRESS"]}}}),
    db.remediationWorkItem.count({where:{organizationId:context.organizationId,status:"BLOCKED"}}),
    db.remediationWorkItem.count({where:{organizationId:context.organizationId,status:"DONE"}}),
    db.remediationWorkItem.count({where:{
      organizationId:context.organizationId,status:{notIn:["DONE","CANCELLED"]},dueAt:{lt:now}
    }}),
    db.remediationWorkItem.count({where:{
      organizationId:context.organizationId,status:{notIn:["DONE","CANCELLED"]},assigneeUserId:null
    }})
  ]);
  return {all,open,blocked,done,overdue,unassigned};
}
export async function untrackedRemediations(context:WorkContext){
  assertPermission(context,"read");
  // Bound the suggestion list to avoid returning an unbounded tenant inventory.
  return db.remediation.findMany({
    where:{organizationId:context.organizationId,workItems:{none:{}}},
    select:{id:true,title:true,status:true,finding:{select:{title:true,severity:true}}},
    orderBy:[{createdAt:"desc"},{id:"desc"}],take:100
  });
}
