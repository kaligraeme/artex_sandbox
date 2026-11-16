const frames = [...document.querySelectorAll('iframe')];
const status = document.getElementById('status');
let estate, mode = 'baseline', animation, generation = 0;
const ready = Promise.all(frames.map(frame => new Promise(resolve => {
  frame.addEventListener('load', async () => {await frame.contentDocument.fonts.ready; resolve();}, {once:true});
})));
function fit() {
  const header = document.querySelector('header').offsetHeight;
  document.querySelector('main').style.height = `${innerHeight-header}px`;
  frames.forEach(frame => {
    const stage=frame.parentElement, available=innerHeight-header-stage.previousElementSibling.offsetHeight;
    const height=frame.contentWindow.comparison.height();
    const scale=Math.min(stage.clientWidth/1440, available/height);
    stage.style.height=`${available}px`;frame.style.height=`${height}px`;frame.style.transform=`scale(${scale})`;
    frame.style.left=`${(stage.clientWidth-1440*scale)/2}px`;
  });
}
function prepare() {
  cancelAnimationFrame(animation); generation++;
  const runs=frames.map((f,i)=>f.contentWindow.comparison.prepare(estate,i?'artex':'pre2023',mode));
  frames.forEach(f=>f.contentWindow.comparison.advance(0));fit();
  return Math.max(...runs.map(r=>r.end));
}
function describe() {return `Seed ${estate.seed} · ${estate.assets.length} assets · Same estate · Shared modeled clock`;}
function runBoth() {
  const end=prepare(), token=generation, duration=Number(document.getElementById('duration').value)*1000;
  const start=performance.now();status.textContent=describe();
  function tick(now) {
    if(token!==generation)return;
    const fraction=Math.min(1,(now-start)/duration);
    frames.forEach(f=>f.contentWindow.comparison.advance(end*fraction));
    if(fraction<1)animation=requestAnimationFrame(tick);
    else status.textContent=describe()+' · Both complete';
  }
  animation=requestAnimationFrame(tick);
}
function generate() {
  const seed=Number(document.getElementById('seed').value);
  if(!Number.isSafeInteger(seed)||seed<1){status.textContent='Enter a positive integer seed.';return;}
  estate=WireEngine.generateEstate({preset:'mixed',seed,seedExercise:true});prepare();status.textContent=describe()+' · Ready';
}
ready.then(()=>{
  const saved=sessionStorage.getItem('wire-comparison-estate');
  if(saved){estate=JSON.parse(saved);document.getElementById('seed').value=estate.seed;prepare();status.textContent=describe()+' · Ready';}
  else generate();
  document.getElementById('run').disabled=false;
  document.getElementById('new').onclick=generate;
  document.getElementById('run').onclick=runBoth;
  document.querySelectorAll('[data-mode]').forEach(button=>button.onclick=()=>{
    mode=button.dataset.mode;document.querySelectorAll('[data-mode]').forEach(b=>b.classList.toggle('selected',b===button));
    prepare();status.textContent=describe()+' · Ready';
  });
  window.addEventListener('resize',fit);
});
document.getElementById('single').onclick=()=>sessionStorage.setItem('wire-return-estate',JSON.stringify(estate));
document.getElementById('fullscreen').onclick=()=>document.fullscreenElement?document.exitFullscreen():document.documentElement.requestFullscreen();
