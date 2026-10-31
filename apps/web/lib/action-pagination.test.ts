import {describe,expect,it} from "vitest";
import {actionPageResult,actionPageUrl,parseActionPageInput} from "./action-pagination";
describe("SME action pagination",()=>{
 it("bounds untrusted page and page size values",()=>{
  expect(parseActionPageInput({page:"-1",pageSize:"100000"})).toMatchObject({page:1,pageSize:20});
  expect(parseActionPageInput({page:"999999",pageSize:"50"})).toMatchObject({page:100000,pageSize:50});
  expect(parseActionPageInput({page:"2",pageSize:"100"})).toMatchObject({page:2,pageSize:100});
 });
 it("normalizes invalid filters without trusting arbitrary query shapes",()=>{
  expect(parseActionPageInput({severity:"UNKNOWN",status:"done",search:["evil"]})).toMatchObject({
   severity:"ALL",status:"attention",search:"",
  });
  expect(parseActionPageInput({severity:"HIGH",status:"verified",search:"  email  "})).toMatchObject({
   severity:"HIGH",status:"verified",search:"email",
  });
 });
 it("returns honest boundaries for empty and final pages",()=>{
  const settings=parseActionPageInput({page:"2",pageSize:"20"});
  expect(actionPageResult(["item"],21,settings)).toMatchObject({
   total:21,totalPages:2,page:2,firstItem:21,lastItem:21,hasPrevious:true,hasNext:false,
  });
  expect(actionPageResult([],0,settings)).toMatchObject({
   total:0,totalPages:1,page:1,firstItem:0,lastItem:0,hasPrevious:false,hasNext:false,
  });
 });
 it("keeps severity and search when navigating pages",()=>{
  const settings=parseActionPageInput({page:"1",pageSize:"50",status:"active",severity:"CRITICAL",search:"domain names"});
  const url=actionPageUrl("/organizations/example/actions",settings,{page:2});
  const parsed=new URL(url,"https://example.invalid");
  expect(parsed.searchParams.get("page")).toBe("2");
  expect(parsed.searchParams.get("search")).toBe("domain names");
  expect(parsed.searchParams.get("severity")).toBe("CRITICAL");
  expect(parsed.searchParams.get("status")).toBe("active");
  expect(parsed.searchParams.get("sort")).toBe("newest");
 });
});

describe("Action ordering pagination",()=>{
  it("accepts supported ordering and refuses arbitrary sort keys",()=>{
    expect(parseActionPageInput({sort:"severity"}).sort).toBe("severity");
    expect(parseActionPageInput({sort:"oldest"}).sort).toBe("oldest");
    expect(parseActionPageInput({sort:"arbitrary"}).sort).toBe("newest");
  });
  it("retains ordering across page links",()=>{
    const settings=parseActionPageInput({sort:"severity",pageSize:"50",status:"all"});
    const url=new URL(actionPageUrl("/actions",settings,{page:3}),"https://example.invalid");
    expect(url.searchParams.get("sort")).toBe("severity");
    expect(url.searchParams.get("page")).toBe("3");
  });
});
