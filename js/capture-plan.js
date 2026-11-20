/* Shared display planning; never modifies or re-simulates the original estate. */
(function(root,factory){const api=factory(typeof module==='object'&&module.exports?require('./run-discovery.js'):root.RunDiscovery);if(typeof module==='object'&&module.exports)module.exports=api;else root.CapturePlan=api;})(typeof globalThis==='object'?globalThis:this,RunDiscovery=>{
  function attempted(event){
    if(RunDiscovery)return RunDiscovery.observed(event);
    if(['revisit','truncated'].includes(event.outcome))return false;
    // Zero-duration eligibility checks are not field attempts. Timed failed jobs are.
    return event.outcome!=='ineligible'||Number.isFinite(event.startSec)&&event.timeSec>event.startSec;
  }
  function create(estate,runs){
    const performed=runs.flatMap(r=>r.events.filter(attempted));
    // A successful zero-time starting foothold is still used infrastructure.
    const used=new Set(performed.flatMap(e=>[e.sourceId,e.targetId]).filter(Boolean));
    const events=performed;
    const controls=runs.flatMap(r=>r.controls).filter(c=>used.has(c.targetId)||used.has(c.scope));
    const initialIds=estate.assets.filter(a=>a.isExternalEntry).map(a=>a.id);
    const ids=new Set([...initialIds,...events.flatMap(e=>[e.sourceId,e.targetId]),...controls.flatMap(e=>[e.targetId,e.scope])].filter(Boolean));
    const assetIds=estate.assets.filter(a=>ids.has(a.id)).map(a=>a.id);
    const edges=new Set(events.map(e=>e.relationshipId).filter(Boolean));
    const relationshipIds=estate.relationships.filter(r=>edges.has(r.id)&&ids.has(r.sourceId)&&ids.has(r.targetId)).map(r=>r.id);
    const chainIds=new Set();
    for(const run of runs){
      const succeeded=run.events.filter(e=>e.outcome==='succeeded');
      const ancestors=new Set(succeeded.filter(e=>e.isProtectedRead||e.actionKind==='encryption').map(e=>e.targetId));
      let changed=true;
      while(changed){changed=false;for(const e of succeeded){if(ancestors.has(e.targetId)&&e.sourceId&&!ancestors.has(e.sourceId)){ancestors.add(e.sourceId);changed=true;}}}
      for(const id of ancestors)chainIds.add(id);
    }
    const entryIds=[...new Set(events.filter(e=>!e.sourceId&&e.outcome==='succeeded').map(e=>e.targetId))];
    return {assetIds,relationshipIds,chainIds:[...chainIds],entryIds};
  }
  function clock(time){const minutes=Math.floor(Math.max(0,time)/60);return `${Math.floor(minutes/60)}h:${String(minutes%60).padStart(2,'0')}m`;}
  return {attempted,create,clock};
});
