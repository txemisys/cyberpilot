import { describe, expect, it } from "vitest";
import { matchDeclaredVulnerabilities } from "./assets-vulnerabilities";
import type { AssetRecord } from "./assets-csv";
const asset: AssetRecord = {assetId:"a",kind:"SERVER",hostname:"a",owner:"ops",os:"ExampleOS",osVersion:"1.2",ip:"",criticality:"HIGH",location:"",lifecycle:"ACTIVE"};
const advisory = { advisoryId:"ADV-1",product:"ExampleOS",version:"1.2",severity:"HIGH" as const,reference:"https://example.test/adv"};
describe("offline vulnerability candidates", () => {
  it("finds exact declared product/version matches but never confirms a vulnerability", () => {
    expect(matchDeclaredVulnerabilities([asset],[advisory])).toEqual([{
      assetId:"a",advisoryId:"ADV-1",severity:"HIGH",state:"CANDIDATE",source:"DECLARED",reference:"https://example.test/adv",
    }]);
  });
  it("does not use partial version matching", () => {
    expect(matchDeclaredVulnerabilities([asset],[{...advisory,version:"1"}])).toEqual([]);
  });
  it("matches case-insensitively and skips retired assets", () => {
    expect(matchDeclaredVulnerabilities([asset],[{...advisory,product:"exampleos"}])).toHaveLength(1);
    expect(matchDeclaredVulnerabilities([{...asset,lifecycle:"RETIRED"}],[advisory])).toEqual([]);
  });
  it("does not invent findings for empty advisory or software fields", () => {
    expect(matchDeclaredVulnerabilities([asset],[{...advisory,advisoryId:""}])).toEqual([]);
    expect(matchDeclaredVulnerabilities([{...asset,osVersion:""}],[advisory])).toEqual([]);
  });
  it("deduplicates identical advisory candidates", () => {
    expect(matchDeclaredVulnerabilities([asset],[advisory,advisory])).toHaveLength(1);
  });
});
