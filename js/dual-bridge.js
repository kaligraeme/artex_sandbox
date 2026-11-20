// Same-origin interface: dual view drives the existing renderer with one clock.
if (new URLSearchParams(location.search).has('embedded')) {
  document.documentElement.classList.add('comparison-embedded');
  const style = document.createElement('style');
  style.textContent = `.comparison-embedded .brand-row,.comparison-embedded .mode-strip,
    .comparison-embedded .run-row,.comparison-embedded #catalog-example {display:none!important}
    .comparison-embedded .canvas-tools {justify-content:flex-end}
    .comparison-embedded,.comparison-embedded body {overflow:hidden}
    .comparison-embedded #viewport {min-height:0;margin:0}
    .comparison-embedded * {transition:none!important}`;
  document.head.append(style);
  window.comparison = {
    prepare(example, actor, mode, options = {}) {
      cancelAnimationFrame(frame);
      estate = structuredClone(example); referenceCase = null; pre2023Group = options.gangId || 'lockbit';
      infrastructureNumber = options.infrastructureNumber || 1; attackerChoice = actor; defense = mode;
      playRun(); cancelAnimationFrame(frame);
      this.done = false;
      return {end: phases.at(-1)?.time || 0, lanes: run.lanes};
    },
    advance(time, {start = false} = {}) {
      if (this.done) return;
      if(time<=0&&phaseIndex===0&&!start){showTime(0);return;}
      while (phaseIndex < phases.length && phases[phaseIndex].time <= time) {
        renderPhase(phases[phaseIndex]); phaseIndex++;
      }
      showTime(Math.min(time, phases.at(-1)?.time || 0));
      if (phaseIndex === phases.length) {finishRun(); this.done = true;}
    },
    height() {return Math.ceil(document.getElementById('viewport').getBoundingClientRect().bottom);},
    redraw() {
      resetGraph();
      phases.slice(0,phaseIndex).forEach(phase=>renderPhase(phase));
      showTime(modeledTime);
    },
    activity() {
      if(!discoveryStarted)return [];
      const priorImpact = event => {
        const earlier = run.events.filter(previous=>previous.outcome==='succeeded' && previous.timeSec<=event.timeSec);
        if(earlier.some(previous=>previous.actionKind==='data_exfiltration'))return ' Earlier data exfiltration remains successful.';
        if(earlier.some(previous=>previous.isProtectedRead))return ' Earlier data access remains successful; it does not by itself confirm export.';
        return '';
      };
      return run.events.map((event,index)=>({event,index})).filter(({event})=>
        !event.policySkipped && event.timeSec<=modeledTime &&
        (event.actionKind==='data_exfiltration' ||
          event.outcome==='ineligible' && event.timeSec>event.startSec && (RunDiscovery.observed(event) || event.analysisKind==='route_review'&&event.sourceId) ||
          RunDiscovery.observed(event) && (event.isProtectedRead || event.finding?.cveId || event.technique)))
        .map(({event,index})=>({id:index,time:event.timeSec,elapsed:formatEstimate(event.timeSec),
          code:event.isProtectedRead?'DATA FOUND':event.actionKind==='data_exfiltration'
            ? event.outcome==='succeeded'?'DATA EXFILTRATED':event.outcome==='blocked'?'EXFILTRATION BLOCKED':'EXFILTRATION STOPPED'
            :event.outcome==='ineligible'?event.analysisKind==='route_review'?'PATH REVIEW':'NO NEW ACCESS'
            :event.outcome==='suppressed'?'ATTEMPT STOPPED'
            :event.finding?.cveId || event.technique,technique:event.technique,
          title:event.isProtectedRead?`${event.finding?.cveId || event.technique || 'Authorized read'} · Sensitive records accessed${event.dataFound?` · ${event.dataFound.records} records`:''}`
            :event.actionKind==='data_exfiltration'?`${event.finding.title}${event.technique?` · ${event.technique}`:''}`
            :event.analysisKind==='route_review'?'Review of an outgoing route'
            :event.outcome==='ineligible'?[event.finding?.cveId || event.finding?.technique,event.finding?.title].filter(Boolean).join(' · ')
            :event.finding?.title || 'Valid account access',
          detail:event.actionKind==='data_exfiltration'?event.outcome==='succeeded'
            ?`${event.dataTransfer.records} records · ${event.dataTransfer.bytes.toLocaleString()} bytes · ${event.dataTransfer.tool} → ${event.dataTransfer.destination}`:event.reason
            :event.analysisKind==='route_review'?`Spent ${formatEstimate(event.timeSec-event.startSec)} reviewing a route; the known foothold lacks its required capability.${priorImpact(event)}`
            :event.outcome==='ineligible'?`Spent ${formatEstimate(event.timeSec-event.startSec)} · This attempt gained no new access. ${event.reason}${priorImpact(event)}`
            :event.outcome==='suppressed'?event.reason:'',
          asset:estate.assets.find(a=>a.id===(event.analysisKind==='route_review'?event.sourceId:event.targetId))?.label || event.targetId,
          outcome:event.outcome})).sort((a,b)=>
            Number(b.code==='DATA EXFILTRATED')-Number(a.code==='DATA EXFILTRATED') || b.time-a.time || b.id-a.id);
    },
    state() {return {estate, events: run.events, time: modeledTime, done: this.done, lanes: run.lanes};}
  };
}
