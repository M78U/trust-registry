import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const html=readFileSync(new URL("../src/index.html",import.meta.url),"utf8");
const repo="https://github.com/M78U/trust-registry";
test("open-source preview exposes repository and version links without changing research boundary",()=>{
  const nav=html.match(/<nav\b[^>]*>[\s\S]*?<\/nav>/)?.[0]??"";
  const hero=html.match(/<section class="hero"[\s\S]*?<\/section>/)?.[0]??"";
  const footer=html.match(/<footer\b[\s\S]*?<\/footer>/)?.[0]??"";
  for(const region of [nav,hero,footer])assert.ok(region.includes('href="'+repo+'"'));
  for(const region of [hero,footer])assert.ok(region.includes('href="'+repo+'/releases/tag/0.1.0"'));
  assert.ok(hero.includes("Developer Preview"));
  assert.ok(hero.includes("仅源码发布"));
  assert.ok(html.includes("NOT ESTABLISHED"));
  assert.ok(html.includes("没有正式信任锚"));
  assert.ok(html.includes('<strong>0</strong><span>已授权信任锚</span>'));
  assert.ok(footer.includes('href="'+repo+'/blob/main/LICENSE"'));
});

test("Homebrew onboarding describes the released ARM64 source-build scope",()=>{
  const section=html.match(/<section id="install"[\s\S]*?<\/section>/)?.[0]??"";
  assert.ok(html.includes('href="#install"'));
  for(const value of ["brew tap m78u/tap","brew install m78u/tap/trust-registry","macOS · Apple Silicon","Go 1.26.11","暂不提供 Bottle 或 Intel 版本","trust-registry init --registry ./local-registry","trust-registry validate --registry ./local-registry","未预置可信 CA、生产信任锚或 TUF 管理工具","https://github.com/M78U/homebrew-tap"])assert.ok(section.includes(value),value);
});
