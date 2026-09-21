import test from 'node:test';
import assert from 'node:assert/strict';
import { investigate } from './loop.ts';
import { runAnalyst, MODEL } from './index.ts';

const brief = {
  incidentId: 'fixture-sqli', ip: '192.0.2.10', openedAt: 1, eventCount: 3,
  events: [{ip:'192.0.2.10', url:'https://demo.invalid/search?q=UNION%20SELECT%20secret', method:'GET', payload:'', timestamp:1}],
  classification: {attackClass:'sqli', severity:80, confidence:0.8, indicators:['union select'], fingerprint:'fixture', pathTemplate:'/search'},
  classesSeen:['sqli'], threatScore:70, stage:'challenge', priorIncidents:2,
  campaign: {fingerprint:'fixture',attackClass:'sqli',ipCount:3,eventCount:3,firstSeen:1,lastSeen:2,ips:['192.0.2.10'],distributed:true},
};
const plan = {kind:'pattern_rule',action:'block',pattern:'union\\s+select',flags:'i',ttlSeconds:300,attackClass:'sqli',diagnosis:'Request contains a SQL union-select sequence; exploitation is unconfirmed.',confidence:0.8};
const inspect = {tool:'inspect_incident'};
const propose = p => ({tool:'propose',plan:p});
function scripted(actions) {
  const calls=[];
  return {calls,source:'mock:scripted',async complete(messages) {
    calls.push(structuredClone(messages));
    if (!actions.length) throw new Error('mock exhausted');
    const next=actions.shift();
    return typeof next === 'function' ? next(messages) : next;
  }};
}
test('tools expose supplied memory and campaign; rejection feeds a revised proposal',async()=>{
  const model=scripted([inspect,{tool:'read_history'},{tool:'read_campaign'},propose({...plan,pattern:'SELECT'}),messages=>{
    assert.match(messages.at(-1).content,/known-benign/);
    return {response:JSON.stringify(propose(plan))};
  }]);
  const result=await investigate(brief,model);
  assert.equal(result.plan.source,'mock:scripted');
  assert.equal(result.trace[1].result.priorIncidents,2);
  assert.equal(result.trace[2].result.distributed,true);
  assert.equal(result.trace[3].result.ok,false);
  assert.equal(result.trace[4].result.ok,true);
});
test('malformed JSON can be corrected and fenced JSON is accepted',async()=>{
  const model=scripted(['oops',inspect,{response:'```json\n'+JSON.stringify(propose(plan))+'\n```'}]);
  assert.equal((await investigate(brief,model)).plan.pattern,plan.pattern);
  assert.match(model.calls[1].at(-1).content,/reasons/);
});
test('requires inspection before accepting a proposal',async()=>{
  const model=scripted([propose(plan),inspect,propose(plan)]);
  const result=await investigate(brief,model);
  assert.match(result.trace[0].result.reasons[0],/inspect_incident/);
});
for (const [name,change] of [
  ['missing diagnosis',{diagnosis:undefined}],
  ['unsupported kind',{kind:'rate_limit'}],
  ['array kind',{kind:['pattern_rule']}],
  ['array class',{attackClass:['sqli']}],
  ['unsupported action',{action:'challenge'}],
  ['invalid confidence',{confidence:2}],
  ['invalid ttl',{ttlSeconds:2}],
  ['invalid class',{attackClass:'invented'}],
  ['stateful flags',{flags:'g'}],
  ['catch-all',{pattern:'.*'}],
  ['ambiguous repeating group',{pattern:'(a|aa)+'}],
  ['nonmatching rule',{pattern:'never-present'}],
]) test('rejects '+name,async()=>{
  const result=await investigate(brief,scripted([inspect,propose({...plan,...change}),propose(plan)]));
  assert.equal(result.trace[1].result.ok,false);
  assert.equal(result.plan.pattern,plan.pattern);
});
test('unknown tools have no authority and source cannot be spoofed',async()=>{
  const result=await investigate(brief,scripted([{tool:'write_kv'},inspect,propose({...plan,source:'verified-production'})]));
  assert.equal(result.trace[0].result.ok,false);
  assert.equal(result.plan.source,'mock:scripted');
});
test('unknown incident still needs real matching evidence',async()=>{
  const unknown={...brief,events:[{...brief.events[0],url:'https://demo.invalid/',payload:'unusual_marker'}]};
  const result=await investigate(unknown,scripted([inspect,propose({...plan,pattern:'unusual_marker',attackClass:'unknown'})]));
  assert.equal(result.plan.attackClass,'unknown');
});
test('observe/log is supported without fabricating a blocking rule',async()=>{
  const result=await investigate(brief,scripted([inspect,propose({...plan,kind:'observe',action:'log'})]));
  assert.equal(result.plan.pattern,undefined);
});
test('bounded attempts reject repeated invalid output',async()=>{
  const model=scripted(Array(6).fill('invalid'));
  await assert.rejects(investigate(brief,model),/step_limit/);
  assert.equal(model.calls.length,6);
});
test('deadline returns without waiting for an unresponsive model',async()=>{
  await assert.rejects(investigate(brief,{source:'mock',complete:()=>new Promise(()=>{})},{budgetMs:15}),/deadline/);
});
test('model errors propagate for Commander fallback',async()=>{
  await assert.rejects(investigate(brief,{source:'mock',complete:async()=>{throw new Error('model offline');}}),/model offline/);
});
test('entrypoint uses only AI and never writes deployment state',async()=>{
  let count=0;
  const env=new Proxy({AI:{async run(model,input){
    assert.equal(model,MODEL);
    assert.equal(input.stream,false);
    return {response:JSON.stringify(count++===0?inspect:propose(plan))};
  }}},{get(target,key){if(key!=='AI')throw new Error('unexpected dependency '+String(key));return target[key];}});
  const result=await runAnalyst(env,brief);
  assert.match(result.source,/^workers-ai:/);
  await assert.rejects(runAnalyst({},brief),/ai_unavailable/);
});

test('double-encoded evidence agrees with Commander signature extraction',async()=>{
  const input={...brief,events:[{...brief.events[0],url:'https://demo.invalid/?q=UNION%2520SELECT'}]};
  assert.equal((await investigate(input,scripted([inspect,propose(plan)]))).plan.pattern,plan.pattern);
});
test('malformed body does not prevent URL decoding',async()=>{
  const input={...brief,events:[{...brief.events[0],payload:'broken%ZZ'}]};
  assert.equal((await investigate(input,scripted([inspect,propose(plan)]))).plan.pattern,plan.pattern);
});
for(const pattern of ['\\w+\\w+Z','\\s+select','a\\s+\\s+Z']) test('rejects costly repetition '+pattern,async()=>{
  const result=await investigate(brief,scripted([inspect,propose({...plan,pattern}),propose(plan)]));
  assert.match(result.trace[1].result.reasons[0],/repetition/);
});
test('repeated reads do not duplicate large evidence in context',async()=>{
  const result=await investigate(brief,scripted([inspect,inspect,propose(plan)]));
  assert.match(result.trace[1].result.reasons[0],/already supplied/);
  assert.equal(result.trace[1].result.events,undefined);
});
test('provider failure preserves earlier rejection trace',async()=>{
  await assert.rejects(investigate(brief,scripted([inspect,propose({...plan,pattern:'SELECT'}),()=>{throw new Error('offline');}])),error=>{
    assert.equal(error.message,'offline');
    assert.equal(error.trace.length,2);
    assert.equal(error.trace[1].result.ok,false);
    return true;
  });
});
test('oversized object responses are rejected before context retention',async()=>{
  const model=scripted([{tool:'inspect_incident',padding:'x'.repeat(16001)},inspect,propose(plan)]);
  const result=await investigate(brief,model);
  assert.match(result.trace[0].result.reasons[0],/too large/);
  assert.ok(model.calls[1].every(m=>m.content.length<16000));
});
test('invalid options fail before any model request',async()=>{
  for(const options of [{budgetMs:NaN},{maxSteps:Infinity},{maxSteps:1.5},{budgetMs:0}]) {
    const model=scripted([]);
    await assert.rejects(investigate(brief,model,options),/invalid_options/);
    assert.equal(model.calls.length,0);
  }
});
test('empty incident cannot cause a blanket IP block',async()=>{
  const result=await investigate({...brief,events:[]},scripted([inspect,propose({...plan,kind:'block_ip'}),propose({...plan,kind:'observe',action:'log'})]));
  assert.match(result.trace[1].result.reasons[0],/without request evidence/);
  assert.equal(result.plan.kind,'observe');
});

test('removed CVE tool is not advertised and cannot call a lookup',async()=>{
  let called=false;
  const model=scripted([{tool:'search_cve',query:'select'},inspect,propose(plan)]);
  const result=await investigate(brief,model,{searchCVE:()=>{called=true;return new Promise(()=>{});}});
  assert.equal(called,false);
  assert.doesNotMatch(model.calls[0][0].content,/search_cve/);
  assert.match(result.trace[0].result.reasons[0],/unknown tool/);
});
