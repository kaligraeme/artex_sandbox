const assert=require('node:assert/strict');
const e=require('../js/wire-engine');
const actors=['lockbit','conti','blackcat','hive','revil'];
const summaries=Object.fromEntries(actors.map(actor=>[actor,{runs:0,footholdRuns:0,lateralRuns:0,
  firstWindowsMethodRuns:{},selectedMethodRuns:{},truncatedRuns:0}]));
for(let seed=1;seed<=50;seed++) {
  const estate=e.generateEstate({preset:'mixed',seed,seedExercise:true});
  const before=JSON.stringify(estate);
  for(const actor of actors) {
    const run=e.simulateWireRun(estate,'baseline',actor),summary=summaries[actor];
    const successes=run.events.filter(x=>x.outcome==='succeeded');
    const lateral=successes.filter(x=>x.sourceId&&x.sourceId!==x.targetId&&x.relationshipId&&x.grantedCapability==='app_exec'&&
      !estate.assets.find(a=>a.id===x.targetId)?.isDecoy);
    for(const hop of lateral)assert(successes.some(x=>x.targetId===hop.sourceId&&x.timeSec<=hop.startSec));
    const method=x=>x.tool==='cobalt_strike'?`cobalt_strike:${x.finding.requiredInterface}`:x.tool||x.technique;
    const firstWindows=lateral.find(x=>x.finding?.kind==='remote_service');
    summary.runs++;summary.footholdRuns+=Number(successes.some(x=>x.grantedCapability==='app_exec'));
    summary.lateralRuns+=Number(lateral.length>0);summary.truncatedRuns+=Number(run.summary.truncated);
    if(firstWindows)summary.firstWindowsMethodRuns[method(firstWindows)]=(summary.firstWindowsMethodRuns[method(firstWindows)]||0)+1;
    for(const selected of new Set(lateral.map(method)))summary.selectedMethodRuns[selected]=(summary.selectedMethodRuns[selected]||0)+1;
    assert.equal(JSON.stringify(estate),before,'Actor selection must preserve the estate');
  }
}
console.log(JSON.stringify({seeds:'1–50',preset:'mixed',seedExercise:true,mode:'baseline',
  interpretation:'Synthetic coverage check; method orders are authored choices, not observed prevalence.',summaries},null,2));
