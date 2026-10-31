import { describe,expect,it } from "vitest";
import {buildScopedActionQuery} from "./action-database-query";
import {parseActionPageInput} from "./action-pagination";

describe("database-scoped SME action search",()=>{
 it("always anchors list and export to the authorized organization",()=>{
  const filter=buildScopedActionQuery("org-a",parseActionPageInput({
   status:"all",search:"domain",severity:"CRITICAL",sort:"severity",
  }));
  expect(filter.where.organizationId).toBe("org-a");
  expect(filter.where.OR).toHaveLength(3);
  expect(filter.where.finding).toEqual({severity:"CRITICAL"});
  expect(filter.orderBy).toEqual([
   {finding:{severity:"desc"}},{createdAt:"desc"},{id:"asc"},
  ]);
 });
 it("requires valid organization context instead of unscoped reads",()=>{
  expect(()=>buildScopedActionQuery("",parseActionPageInput({}))).toThrow();
 });
 it("never treats a proposed remediation as verified",()=>{
  const attention=buildScopedActionQuery("org",parseActionPageInput({status:"attention"}));
  const verified=buildScopedActionQuery("org",parseActionPageInput({status:"verified"}));
  expect(attention.where.status).toEqual({in:["PROPOSED","APPROVED","FAILED","SUCCEEDED"]});
  expect(verified.where.status).toEqual({in:["VERIFIED"]});
 });
 it("keeps matching and ordering deterministic when pagination changes",()=>{
  const filters=parseActionPageInput({status:"active",sort:"oldest",page:"9",pageSize:"50"});
  const query=buildScopedActionQuery("org",filters);
  expect(query.where.status).toEqual({in:["EXECUTING"]});
  expect(query.orderBy).toEqual([{createdAt:"asc"},{id:"asc"}]);
 });
 it("does not add untrusted search conditions to an empty query",()=>{
  const query=buildScopedActionQuery("org",parseActionPageInput({search:["forged"]}));
  expect(query.where).toEqual({organizationId:"org",status:{in:["PROPOSED","APPROVED","FAILED","SUCCEEDED"]}});
 });
});
