const assert = require('node:assert/strict');
const e = require('../js/wire-engine.js');

function fixture({decoy = false, secondEntry = false} = {}) {
  const assets = [0,1,2,3].map(layer => ({id:`a${layer}`,groupId:'test',label:`Asset ${layer}`,product:'Fixture',assumedVersion:'1',layerIdx:layer,
    interfaces:['https'],isExternalEntry:layer===0,conditions:{}}));
  const findings = assets.map(a=>({id:`f-${a.id}`,assetId:a.id,kind:'anonymous_access',yieldsCapability:a.layerIdx===3?'data_read':'app_exec'}));
  const relationships = [1,2,3].map(layer=>({id:`r${layer}`,sourceId:`a${layer-1}`,targetId:`a${layer}`,protocol:'https',direction:'outbound',requiredSourceCapability:'app_exec'}));
  if (decoy) {
    assets.push({...assets[1],id:'decoy',isDecoy:true});
    findings.push({id:'fd',assetId:'decoy',kind:'anonymous_access',yieldsCapability:'decoy_alert'});
    relationships.unshift({id:'rd',sourceId:'a0',targetId:'decoy',protocol:'https',direction:'outbound',requiredSourceCapability:'app_exec'});
  }
  if (secondEntry) {
    assets.push({...assets[0],id:'other'});
    findings.push({id:'fo',assetId:'other',kind:'anonymous_access',yieldsCapability:'app_exec'});
  }
  return {schemaVersion:e.SCHEMA_VERSION,seed:9,preset:'comparison',assets,findings,relationships,credentials:[],
    actionOrder:assets.map(a=>a.id),defensePosture:{telemetryLayers:[0,1,2,3],decoys:decoy?[{assetId:'decoy'}]:[]}};
}
const opts = {actionDurations:[0,10,20,30],responseDelay:60,decisionDelay:0};
const run = (estate,mode,options={}) => e.simulateWireRun(estate,mode,'artex',{...opts,...options});
const read = r=>r.events.find(x=>x.outcome==='succeeded'&&x.grantedCapability==='data_read');
// Scope, causality, exact ties, failure and latency are independent from actor labels.
const x=fixture();
assert(read(run(x,'soc')), 'Late enforcement preserves the read');
assert(!read(run(x,'soc',{responseDelay:30})), 'Enforcement before the read cancels its effect');
assert(!read(run(x,'soc',{responseDelay:50})), 'Enforcement ties precede action effects');
assert(read(run(x,'soc',{responseDelay:51})), 'One second after impact is too late');
assert(read(run(x,'soc',{responseDelay:0,enforcementSucceeds:false})));
assert(read(run(x,'soc',{responseDelay:0,responseAuthority:false})));
assert(read(run(x,'soc',{responseDelay:0,responseScope:'unrelated'})));
const failed=run(x,'soc',{responseDelay:0,enforcementSucceeds:false});
assert(failed.controls.some(c=>c.control==='failed'));
assert.equal(failed.result.containedSessions,0);
for (const mode of ['baseline','patch','canaries','soc','soc-canary','combined']) {
  const a=run(x,mode,{responseAuthority:false});
  assert.deepEqual(a,run(x,mode,{responseAuthority:false}), 'Replay is deterministic');
  assert.equal(a.summary.explorationLimit,1000);
  assert.equal(a.summary.evaluatedTransitions,4, 'No defense-dependent exploration allowance');
  assert(read(a));
}
// Equal total duration, different final allocation changes the outcome without changing actor identity.
assert(read(run(x,'soc',{actionDurations:[0,50,5,5],responseDelay:20})));
assert(!read(run(x,'soc',{actionDurations:[0,10,20,30],responseDelay:20})));
const d=fixture({decoy:true});
const before=JSON.stringify(d);
const alert=run(d,'canaries');
assert(alert.controls.some(c=>c.source==='canary'));
assert(!alert.controls.some(c=>c.control==='enforced'));
assert(read(alert));
const combined=run(d,'combined');
assert(combined.controls.some(c=>c.source==='canary'));
assert(combined.controls.some(c=>c.control==='enforced'));
assert.equal(JSON.stringify(d),before, 'Comparisons do not mutate the estate');
// Common transition ceiling reports pending work even if impact is already established.
const pending=fixture();
pending.assets.push({...pending.assets[3],id:'extra'});
pending.findings.push({id:'fx',assetId:'extra',kind:'anonymous_access',yieldsCapability:'data_read'});
pending.relationships.push({...pending.relationships[2],id:'rx',targetId:'extra'});
pending.actionOrder.push('extra');
const limited=run(pending,'baseline',{explorationLimit:4});
assert.equal(limited.summary.dataReached,true);
assert.equal(limited.summary.truncated,true);
assert.equal(limited.result.style,'breached');
assert.equal(limited.result.incomplete,true);
// Validate all IDs eagerly, including one-item orders and unknown CVEs even in baseline.
for (const order of [['wrong'],['a0','a0'],['a0']]) {
  const bad=fixture();bad.actionOrder=order;
  assert.throws(()=>run(bad,'baseline'),/actionOrder/);
}
const rogue=fixture();rogue.findings[0]={...rogue.findings[0],kind:'cve',cveId:'CVE-9999-0001'};
assert.throws(()=>run(rogue,'baseline'),/control coverage/);
const noOrder=fixture();delete noOrder.actionOrder;assert(read(run(noOrder,'baseline')));
const scopes=run(fixture({secondEntry:true}),'soc',{responseDelay:0});
assert.equal(scopes.result.allContained,false, 'One enforcement does not contain every established session');
assert.equal(scopes.result.style,'');
assert.equal(run(x,'baseline').result.style,'breached');
const earlyDecoy=fixture({decoy:true});earlyDecoy.defensePosture.telemetryLayers=[2,3];
const weakSoc=run(earlyDecoy,'soc',{responseDelay:40});
const decoySoc=run(earlyDecoy,'soc-canary',{responseDelay:40});
assert(read(weakSoc));assert(!read(decoySoc), 'Decoy evidence can precede sparse boundary telemetry');
const untouched=structuredClone(earlyDecoy);untouched.relationships=untouched.relationships.filter(r=>r.targetId!=='decoy');
assert(!run(untouched,'soc-canary').controls.some(c=>c.source==='canary'));
const patchEstate=e.generateEstate({preset:'demo',seed:777});
for(const mode of ['patch','combined']) assert(!e.simulateWireRun(patchEstate,mode,'lockbit').summary.dataReached);
for(const options of [{actionDurations:[0,-1,2,3]},{attackerProfile:{maxConcurrentBranches:0}},{responseDelay:-1},{explorationLimit:0}]) assert.throws(()=>run(x,'baseline',options));
assert(read(e.simulateWireRun(x,'soc','lockbit',{...opts,responseDelay:100})),'Conventional attack can beat late response');
assert(!read(run(x,'soc',{responseDelay:0})),'Agentic attack can lose to early response');
const lateDecoy=fixture({decoy:true});
lateDecoy.defensePosture.telemetryLayers=[];
lateDecoy.assets.find(a=>a.id==='decoy').layerIdx=3;
lateDecoy.relationships.find(r=>r.targetId==='decoy').sourceId='a2';
assert(read(run(lateDecoy,'soc-canary',{responseDelay:20})),'Late decoy cannot undo the data read');
for(const workers of [1,3]){
  const scheduled=run(fixture({secondEntry:true}),'baseline',{actionDurations:[10,20,20,20],attackerProfile:{maxConcurrentBranches:workers}});
  assert.equal(scheduled.attackerProfile.adaptiveWafEvasion,true,'Worker override preserves other capabilities');
  const jobs=[...new Map(scheduled.events.filter(x=>x.timeSec>x.startSec).map(x=>[`${x.sourceId}:${x.targetId}:${x.startSec}`,x])).values()];
  for(const job of jobs){
    const midpoint=(job.startSec+job.timeSec)/2;
    assert(jobs.filter(x=>x.startSec<=midpoint&&x.timeSec>midpoint).length<=workers,'No worker overbooking');
  }
}
const undeployed=fixture({decoy:true});undeployed.defensePosture.decoys=[{assetId:'a3'}];
assert.throws(()=>run(undeployed,'combined'),/Undeployed decoy/);
console.log('PASS remediation: budgets, response lifecycle, ties, scope, decoys, replay, validation');
