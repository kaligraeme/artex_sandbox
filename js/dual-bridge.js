// Same-origin interface: dual view drives the existing renderer with one clock.
if (new URLSearchParams(location.search).has('embedded')) {
  document.documentElement.classList.add('comparison-embedded');
  const style = document.createElement('style');
  style.textContent = `.comparison-embedded .brand-row,.comparison-embedded .mode-strip,
    .comparison-embedded .run-row {display:none!important}
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
      return AttackFeed.activity({estate, run, modeledTime, discoveryStarted, done:this.done, formatEstimate});
    },
    state() {return {estate, events: run.events, time: modeledTime, done: this.done, lanes: run.lanes};}
  };
}
