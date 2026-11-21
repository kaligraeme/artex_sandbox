// Shared event projection and feed rendering for both demo views.
window.AttackFeed = {
  activity({estate, run, modeledTime, discoveryStarted, done, formatEstimate}) {
      if(!discoveryStarted)return [];
      const priorImpact = event => {
        const earlier = run.events.filter(previous=>previous.outcome==='succeeded' && previous.timeSec<=event.timeSec);
        if(earlier.some(previous=>previous.actionKind==='data_exfiltration'))return ' Earlier data exfiltration remains successful.';
        if(earlier.some(previous=>previous.isProtectedRead))return ' Earlier data access remains successful; it does not by itself confirm export.';
        return '';
      };
      const activity = run.events.map((event,index)=>({event,index})).filter(({event})=>
        !event.policySkipped && event.timeSec<=modeledTime &&
        (event.actionKind==='data_exfiltration' ||
          event.outcome==='ineligible' && event.timeSec>event.startSec && (RunDiscovery.observed(event) || event.analysisKind==='route_review'&&event.sourceId) ||
          RunDiscovery.observed(event) && (event.isProtectedRead || event.finding?.cveId || event.technique)))
        .map(({event,index})=>({id:index,time:event.timeSec,elapsed:formatEstimate(event.timeSec),isExport:event.actionKind==='data_exfiltration',
          code:event.isProtectedRead?'DATA FOUND':event.actionKind==='data_exfiltration'
            ? event.outcome==='succeeded'?'DATA EXFILTRATED':event.outcome==='blocked'?'EXFILTRATION BLOCKED':event.outcome==='ineligible'?'EXPORT NOT ATTEMPTED':'EXFILTRATION STOPPED'
            :event.outcome==='ineligible'?event.analysisKind==='route_review'?'PATH REVIEW':'NO NEW ACCESS'
            :event.outcome==='suppressed'?'ATTEMPT STOPPED'
            :event.finding?.cveId || event.technique,technique:event.technique,
          title:event.isProtectedRead?`${event.finding?.cveId || event.technique || 'Authorized read'} · Sensitive records accessed${event.dataFound?.records>0?` · ${event.dataFound.records} records`:''}`
            :event.actionKind==='data_exfiltration'?`${event.finding.title}${event.technique?` · ${event.technique}`:''}`
            :event.analysisKind==='route_review'?'Review of an outgoing route'
            :event.outcome==='ineligible'?[event.finding?.cveId || event.finding?.technique,event.finding?.title].filter(Boolean).join(' · ')
            :event.finding?.title || 'Valid account access',
          detail:event.actionKind==='data_exfiltration'?event.outcome==='succeeded'
            ?`${event.dataTransfer.records==null?'Record count unknown':`${event.dataTransfer.records} records`} · ${event.dataTransfer.bytes==null?'Data size unknown':`${event.dataTransfer.bytes.toLocaleString()} bytes`} · ${event.dataTransfer.tool} → ${event.dataTransfer.destination}`:event.reason
            :event.analysisKind==='route_review'?`Spent ${formatEstimate(event.timeSec-event.startSec)} reviewing a route; the known foothold lacks its required capability.${priorImpact(event)}`
            :event.outcome==='ineligible'?`Spent ${formatEstimate(event.timeSec-event.startSec)} · This attempt gained no new access. ${event.reason}${priorImpact(event)}`
            :event.outcome==='suppressed'?event.reason:'',
          asset:estate.assets.find(a=>a.id===(event.analysisKind==='route_review'?event.sourceId:event.targetId))?.label || event.targetId,
          outcome:event.outcome})).sort((a,b)=>
            Number(b.isExport)-Number(a.isExport) || b.time-a.time || b.id-a.id);
      const lateral=done && RunDiscovery.lateralStatus(estate,run);
      if(lateral)activity.push({id:run.events.length,time:modeledTime,elapsed:formatEstimate(modeledTime),isExport:false,
        code:'LATERAL MOVEMENT',title:lateral.summary,detail:lateral.detail,
        asset:lateral.reachedTargets.length?'Other lateral access succeeded':'Established foothold',outcome:'ineligible'});
      return activity.sort((a,b)=>Number(b.isExport)-Number(a.isExport) || b.time-a.time || b.id-a.id);
  },
  render(feed, activity) {
    const list=feed.querySelector('ol');
    const signature=activity.map(item=>item.id).join(',');
    if(list.dataset.signature===signature)return;
    list.dataset.signature=signature;
    const offset=feed.scrollTop, previousHeight=feed.scrollHeight;
    const entries=activity.map(item=>{
      const entry=document.createElement('li');entry.dataset.eventId=item.id;entry.dataset.time=item.time;
      const code=document.createElement('strong');code.textContent=item.code;
      const title=document.createElement('span');title.textContent=item.title;
      const asset=document.createElement('span');asset.textContent=item.asset;
      const detail=document.createElement('span');detail.textContent=item.detail || '';
      const when=document.createElement('time');when.textContent=`${item.elapsed} elapsed · ${item.outcome==='ineligible'?(item.isExport?'not attempted':'no new access'):item.outcome}`;
      entry.append(code,title,asset,detail,when);return entry;
    });
    list.replaceChildren(...entries);feed.querySelector('.feed-empty').hidden=activity.length>0;
    feed.scrollTop=offset>0?offset+feed.scrollHeight-previousHeight:0;
  }
};
