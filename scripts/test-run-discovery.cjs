const assert=require('node:assert/strict');
const d=require('../js/run-discovery');
const e=require('../js/wire-engine');
const asset=(id,isExternalEntry=false)=>({id,isExternalEntry});
const edge=(id,sourceId,targetId)=>({id,sourceId,targetId});
const estate={assets:[asset('entry',true),asset('public-unused',true),asset('app'),asset('failed'),asset('canceled'),asset('in-flight'),asset('unreachable'),asset('policy-only'),asset('unused')],
  relationships:[edge('entry-app','entry','app'),edge('app-failed','app','failed'),edge('app-canceled','app','canceled'),edge('app-flight','app','in-flight'),edge('unused-edge','app','unused')]};
const run={events:[
  {targetId:'entry',outcome:'succeeded',startSec:0,timeSec:0},
  {sourceId:'entry',targetId:'app',relationshipId:'entry-app',outcome:'blocked',startSec:10,timeSec:20},
  {sourceId:'app',targetId:'failed',relationshipId:'app-failed',outcome:'ineligible',startSec:20,timeSec:30,reason:'No modeled access established'},
  {sourceId:'app',targetId:'canceled',relationshipId:'app-canceled',outcome:'suppressed',suppressionPhase:'queued',startSec:30,timeSec:30},
  {sourceId:'app',targetId:'in-flight',relationshipId:'app-flight',outcome:'suppressed',suppressionPhase:'in_flight',startSec:25,timeSec:28},
  {sourceId:'app',targetId:'unreachable',outcome:'ineligible',startSec:20,timeSec:30,reason:'Required source capability is not established.'},
  {targetId:'policy-only',outcome:'ineligible',policySkipped:true,startSec:0,timeSec:100},
  {targetId:'public-unused',outcome:'ineligible',startSec:0,timeSec:0},
],controls:[{targetId:'unused',scope:'entry',control:'enforced',timeSec:35}]};
const snapshot=JSON.stringify({estate,run});
const plan=d.create(estate,run);
assert.deepEqual(plan.assetIds,['entry','public-unused','app','failed','in-flight']);
assert.deepEqual(plan.relationshipIds,['entry-app','app-failed','app-flight']);
assert.deepEqual(d.at(plan,0,false).assetIds,['entry','public-unused']);
assert.deepEqual(d.at(plan,9).assetIds,['entry','public-unused']);
assert.deepEqual(d.at(plan,10).assetIds,['entry','public-unused','app'],'Target appears at probe start, before its outcome');
assert.deepEqual(d.at(plan,20).assetIds,['entry','public-unused','app','failed']);
assert.deepEqual(d.at(plan,25).assetIds,['entry','public-unused','app','failed','in-flight']);
assert(!d.observed({...run.events[2],outcome:'revisit'}));
assert.equal(JSON.stringify({estate,run}),snapshot);
const empty=d.create(estate,{events:[],controls:run.controls});
assert.deepEqual(empty.assetIds,['entry','public-unused'],'Public surfaces remain known; a control cannot disclose untouched internals');
for(let seed=1;seed<=15;seed++) {
  const scenario=e.generateEstate({seed,seedExercise:true});
  const before=JSON.stringify(scenario);
  const sharedInitial=scenario.assets.filter(a=>a.isExternalEntry).map(a=>a.id);
  for(const actor of ['lockbit','conti','blackcat','hive','revil','artex'])for(const mode of ['baseline','patch','soc','combined']) {
    const result=e.simulateWireRun(scenario,mode,actor),original=JSON.stringify(result);
    const p=d.create(scenario,result);
    assert.deepEqual(p.initialAssetIds,sharedInitial,'Every gang and defense starts from the same estate-owned visibility');
    const final=d.at(p,Infinity);
    assert.equal(new Set(final.assetIds).size,p.assetIds.length);
    assert(p.initialAssetIds.every(id=>scenario.assets.some(a=>a.id===id&&a.isExternalEntry)));
    for(const event of result.events.filter(d.observed)) {
      assert(final.known.has(event.targetId));
      if(event.relationshipId)assert(final.relationshipIds.includes(event.relationshipId));
    }
    const points=[...new Set([0,...Object.values(p.assetTimes)])].sort((a,b)=>a-b);
    let known=new Set();
    for(const time of points) {
      const next=d.at(p,time).known;
      assert([...known].every(id=>next.has(id)),'Knowledge grows monotonically within a run');known=next;
    }
    assert.equal(JSON.stringify(result),original,'Display planning cannot change events, time, budgets or outcomes');
  }
  assert.equal(JSON.stringify(scenario),before);
}
console.log('PASS discovery: external start, timed growth, failed probes, queued/in-flight containment, no policy/unused leaks, immutable model and 360 run views');
