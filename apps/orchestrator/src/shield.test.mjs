import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { handleShieldRequest } from './shield.ts';
import { classify } from './commander/fingerprint.ts';

function setup(overrides={}) {
  const events=[], forwarded=[];
  const env={
    DEMO_UPSTREAM:'http://target.invalid:3001',
    RULES_KV:{get:async key=>key==='waf:patterns'?JSON.stringify(overrides.rules??[]):null},
    ANALYSIS_QUEUE:{send:async event=>events.push(event)},
    ...overrides.env,
  };
  return {env,events,forwarded,fetchOrigin:async req=>{
    forwarded.push({url:req.url,method:req.method,body:await req.text(),redirect:req.redirect});
    return new Response('target response',{status:201});
  }};
}
for(const path of ['//other.invalid/login','/login?q=1','/a/%2f%2fother.invalid']) test('pins target host for '+path,async()=>{
  const s=setup();
  await handleShieldRequest(new Request('https://shield.invalid'+path),s.env,s.fetchOrigin);
  assert.equal(new URL(s.forwarded[0].url).origin,'http://target.invalid:3001');
  assert.equal(s.forwarded[0].redirect,'manual');
});
for(const upstream of [undefined,'','invalid','file:///etc/passwd','https://user:password@target.invalid']) test('rejects missing/invalid target '+String(upstream),async()=>{
  const s=setup({env:{DEMO_UPSTREAM:upstream}});
  const response=await handleShieldRequest(new Request('https://shield.invalid/login'),s.env,s.fetchOrigin);
  assert.equal(response.status,503);
  assert.equal(s.forwarded.length,0);
});
test('preserves legitimate request body, query and upstream response',async()=>{
  const s=setup();
  const body=JSON.stringify({username:'alice',password:'correct-password'});
  const response=await handleShieldRequest(new Request('https://shield.invalid/login?next=home',{method:'POST',headers:{'content-type':'application/json'},body}),s.env,s.fetchOrigin);
  assert.equal(response.status,201);
  assert.equal(s.forwarded[0].body,body);
  assert.equal(s.forwarded[0].method,'POST');
  assert.equal(new URL(s.forwarded[0].url).search,'?next=home');
  assert.equal(s.events.length,0);
});
test('actual SQLite login bypass is queued and classified as SQL injection',async()=>{
  const db=new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE users(username TEXT,password TEXT,role TEXT); INSERT INTO users VALUES('admin','secret','admin')");
    const username="admin' -- ", password='incorrect';
    const row=db.prepare("SELECT * FROM users WHERE username = '"+username+"' AND password = '"+password+"'").get();
    assert.equal(row.role,'admin');
    const s=setup();
    await handleShieldRequest(new Request('https://shield.invalid/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,password})}),s.env,s.fetchOrigin);
    assert.equal(s.events.length,1);
    assert.equal(classify(s.events[0]).attackClass,'sqli');
  } finally {db.close();}
});
test('encoded form login bypass is queued',async()=>{
  const s=setup();
  await handleShieldRequest(new Request('https://shield.invalid/login',{method:'POST',body:new URLSearchParams({username:"admin' -- ",password:'wrong'})}),s.env,s.fetchOrigin);
  assert.equal(s.events.length,1);
});
test('scanner user agent reaches Commander',async()=>{
  const s=setup();
  await handleShieldRequest(new Request('https://shield.invalid/',{headers:{'user-agent':'sqlmap'}}),s.env,s.fetchOrigin);
  assert.equal(s.events.length,1);
  assert.equal(s.events[0].userAgent,'sqlmap');
});
for(const first of ['log','challenge']) test(first+' pattern cannot mask a blocking pattern',async()=>{
  const rule={id:'one',pattern:'bad-marker',flags:'i',expiresAt:Date.now()+60000};
  const s=setup({rules:[{...rule,action:first},{...rule,id:'two',action:'block'}]});
  const response=await handleShieldRequest(new Request('https://shield.invalid/?q=bad-marker'),s.env,s.fetchOrigin);
  assert.equal(response.status,403);
  assert.equal(s.forwarded.length,0);
});
test('expired blocking rule does not block legitimate forwarding',async()=>{
  const s=setup({rules:[{pattern:'marker',flags:'',action:'block',expiresAt:Date.now()-1}]});
  assert.equal((await handleShieldRequest(new Request('https://shield.invalid/?q=marker'),s.env,s.fetchOrigin)).status,201);
});

test('own hostname is not scanned: benign login on localhost is clean, loopback in the query is still SSRF',()=>{
  const benign=classify({ip:'203.0.113.9',url:'http://localhost:8787/login',method:'POST',payload:'username=alice&password=pw',timestamp:0});
  assert.equal(benign.attackClass,'unknown');
  const ssrf=classify({ip:'203.0.113.9',url:'http://localhost:8787/fetch?url=http://127.0.0.1:8080/admin',method:'GET',payload:'',timestamp:0});
  assert.equal(ssrf.attackClass,'ssrf');
});
