import {readIntegratedActions,
  type ActionActor} from "./integrated-action-service";
import {buildSlaOperationalReport,verifySlaOperationalReport,
  defaultSlaCalendar,defaultSlaRules} from "./offline-action-sla";
export async function collectOfflineActionSla(actor:ActionActor,
 asOf=new Date().toISOString()){
 const data=await readIntegratedActions(actor,asOf);
 const report=buildSlaOperationalReport({
   organizationId:actor.organizationId,asOf,
   actions:data.actions,events:data.history,
   calendar:defaultSlaCalendar(),rules:defaultSlaRules(),
   actionLimit:500,eventLimit:2000,
   truncatedActions:data.truncated,truncatedEvents:data.truncated,
 });
 if(!verifySlaOperationalReport(report,actor.organizationId).valid)
   throw Error("SLA_INTEGRITY_FAILED");
 return report;
}
