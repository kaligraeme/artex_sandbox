// Same-origin interface: dual view drives the existing renderer with one clock.
if (new URLSearchParams(location.search).has('embedded')) {
  document.documentElement.classList.add('comparison-embedded');
  const style = document.createElement('style');
  style.textContent = `.comparison-embedded .brand-row,.comparison-embedded .mode-strip,
    .comparison-embedded .run-row,.comparison-embedded #catalog-example {display:none!important}
    .comparison-embedded .canvas-tools {justify-content:flex-end}
    .comparison-embedded #viewport {min-height:0}
    .comparison-embedded * {transition:none!important}`;
  document.head.append(style);
  window.comparison = {
    prepare(example, actor, mode) {
      cancelAnimationFrame(frame);
      estate = structuredClone(example); referenceCase = null; pre2023Group = 'lockbit';
      infrastructureNumber = 1; attackerChoice = actor; defense = mode;
      playRun(); cancelAnimationFrame(frame);
      this.done = false;
      return {end: phases.at(-1)?.time || 0, lanes: run.lanes};
    },
    advance(time) {
      if (this.done) return;
      if(time<=0&&phaseIndex===0){showTime(0);return;}
      while (phaseIndex < phases.length && phases[phaseIndex].time <= time) {
        renderPhase(phases[phaseIndex]); phaseIndex++;
      }
      showTime(Math.min(time, phases.at(-1)?.time || 0));
      if (phaseIndex === phases.length) {finishRun(); this.done = true;}
    },
    height() {return Math.ceil(document.getElementById('viewport').getBoundingClientRect().bottom);},
    state() {return {estate, events: run.events, time: modeledTime, done: this.done, lanes: run.lanes};}
  };
}
