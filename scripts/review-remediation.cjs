// Reproducible model sensitivity/invariant sweep; these are simulated counts, not efficacy estimates.
const assert=require('node:assert/strict');
const e=require('../js/wire-engine.js');
const modes=['baseline','patch','canaries','soc','soc-canary','combined'];
const counts=Object.fromEntries(['lockbit','artex'].map(a=>[a,Object.fromEntries(modes.map(m=>[m,{reads:0,incomplete:0}]))]));
let runs=0;
for(const preset of ['mixed','demo','logs'])for(let seed=1;seed<=200;seed++){
  const estate=e.generateEstate({preset,seed,seedExercise:true});
  const original=JSON.stringify(estate);
  for(const actor of ['lockbit','artex'])for(const mode of modes){
    const r=e.simulateWireRun(estate,mode,actor);runs++;
    const bucket=counts[actor][mode];bucket.reads+=Number(r.summary.dataReached);bucket.incomplete+=Number(r.summary.truncated);
    assert.equal(r.summary.explorationLimit,1000);
    assert(r.summary.evaluatedTransitions<=1000);
    assert.equal(r.summary.dataReached,r.events.some(x=>x.outcome==='succeeded'&&x.isProtectedRead));
    if(mode==='canaries'||mode==='baseline'||mode==='patch')assert(!r.controls.some(c=>c.control==='enforced'));
    const reached=new Map();
    for(const event of r.events){
      assert(Number.isFinite(event.timeSec)&&event.timeSec>=0);
      assert(event.startSec<=event.timeSec);
      if(event.sourceId&&event.outcome==='succeeded'){
        assert(reached.has(event.sourceId),`source not reached: ${preset}/${seed}/${actor}/${mode}`);
        assert(reached.get(event.sourceId)<=event.startSec);
      }
      if(event.outcome==='succeeded'){
        if(!reached.has(event.targetId))reached.set(event.targetId,event.timeSec);
        assert(!r.controls.some(c=>c.control==='enforced'&&c.scope===event.scope&&c.timeSec<=event.timeSec));
      }
    }
    for(const c of r.controls.filter(c=>c.source==='canary'))assert(estate.assets.some(a=>a.isDecoy&&a.id===c.targetId));
    assert.equal(JSON.stringify(estate),original);
  }
}
console.log(JSON.stringify({presets:['mixed','demo','logs'],seeds:[1,200],runs,counts,invariants:'PASS: causal prerequisites, enforcement, budgets, real decoys, unchanged estate'},null,2));
