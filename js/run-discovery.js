// A trace-derived display plan. Never removes assets or actions from the simulation.
(function(root,factory){if(typeof module==='object'&&module.exports)module.exports=factory();else root.RunDiscovery=factory();})(typeof self!=='undefined'?self:this,function(){
  function observed(event) {
    if(event.policySkipped || ['revisit','truncated'].includes(event.outcome))return false;
    if(event.outcome==='suppressed' && event.suppressionPhase==='queued')return false;
    if(event.outcome==='ineligible' || event.outcome==='suppressed') {
      if(!Number.isFinite(event.startSec) || !Number.isFinite(event.timeSec) || event.timeSec<=event.startSec)return false;
      // Missing source access or an invalid route is not a probe of the target.
      if(/source capability|No directed relationship|Protocol mismatch|Relationship direction|endpoints do not match/i.test(event.reason||''))return false;
    }
    return ['succeeded','blocked','alert_only','ineligible','suppressed'].includes(event.outcome);
  }
  function create(estate,run) {
    const assets=new Map(estate.assets.map(a=>[a.id,a]));
    const relationships=new Map(estate.relationships.map(r=>[r.id,r]));
    const assetTimes={},relationshipTimes={};
    const remember=(times,id,time)=>{if(id)times[id]=Math.min(times[id]??Infinity,time);};
    for(const event of run.events.filter(observed)) {
      const time=Number.isFinite(event.startSec)?event.startSec:Number.isFinite(event.timeSec)?event.timeSec:0;
      if(assets.has(event.targetId))remember(assetTimes,event.targetId,time);
      if(assets.has(event.sourceId))remember(assetTimes,event.sourceId,time);
      const rel=relationships.get(event.relationshipId);
      if(rel && rel.sourceId===event.sourceId && rel.targetId===event.targetId)remember(relationshipTimes,rel.id,time);
    }
    // Starting knowledge belongs to the estate, not to an attacker's future trace.
    const initialAssetIds=estate.assets.filter(a=>a.isExternalEntry).map(a=>a.id);
    for(const id of initialAssetIds)assetTimes[id]=0;
    return {assetIds:estate.assets.filter(a=>Object.hasOwn(assetTimes,a.id)).map(a=>a.id),
      relationshipIds:estate.relationships.filter(r=>Object.hasOwn(relationshipTimes,r.id)).map(r=>r.id),
      initialAssetIds,assetTimes,relationshipTimes};
  }
  function at(plan,time,started=true) {
    const assetIds=started?plan.assetIds.filter(id=>plan.assetTimes[id]<=time):plan.initialAssetIds;
    const known=new Set(assetIds);
    return {assetIds,relationshipIds:started?plan.relationshipIds.filter(id=>plan.relationshipTimes[id]<=time):[],known};
  }
  return {observed,create,at};
});
