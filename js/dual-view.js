const frames = [...document.querySelectorAll('iframe')];
const status = document.getElementById('status');
let estate, mode = 'baseline', animation, generation = 0;
const gangNames = {lockbit:'LockBit', conti:'Conti', blackcat:'BlackCat', hive:'Hive', revil:'REvil'};
let gangId = 'lockbit', gangDeck = [], infrastructureNumber = 1;
function nextGang() {
  if (!gangDeck.length) gangDeck = Object.keys(gangNames).filter(id=>id!==gangId);
  return gangDeck.splice(Math.floor(Math.random()*gangDeck.length),1)[0];
}
let fittedHeights = '';
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
  fittedHeights=frames.map(frame=>frame.contentWindow.comparison.height()).join(',');
}
function prepare() {
  cancelAnimationFrame(animation); generation++;
  document.getElementById('gang-profile').textContent=`${gangNames[gangId]}-style · One attacker`;
  const runs=frames.map((f,i)=>f.contentWindow.comparison.prepare(estate,i?'artex':'pre2023',mode,{gangId,infrastructureNumber}));
  frames.forEach(f=>f.contentWindow.comparison.advance(0));fit();
  return Math.max(...runs.map(r=>r.end));
}
function describe() {return `Seed ${estate.seed} · ${estate.assets.length} assets · Same estate · Shared modeled clock`;}
function runBoth() {
  const end=prepare(), token=generation, duration=Number(document.getElementById('duration').value)*1000;
  frames.forEach(f=>f.contentWindow.comparison.advance(0,{start:true}));fit();
  const start=performance.now();status.textContent=describe();
  if(end===0){status.textContent=describe()+' · Both complete';return;}
  function tick(now) {
    if(token!==generation)return;
    const fraction=Math.min(1,(now-start)/duration);
    frames.forEach(f=>f.contentWindow.comparison.advance(end*fraction));
    if(frames.map(f=>f.contentWindow.comparison.height()).join(',')!==fittedHeights)fit();
    if(fraction<1)animation=requestAnimationFrame(tick);
    else status.textContent=describe()+' · Both complete';
  }
  animation=requestAnimationFrame(tick);
}
function generate() {
  const seed=Number(document.getElementById('seed').value);
  if(!Number.isSafeInteger(seed)||seed<1||seed>4294967295){status.textContent='Enter an integer seed from 1 to 4294967295.';return;}
  estate=WireEngine.generateEstate({preset:'mixed',seed,seedExercise:true});prepare();status.textContent=describe()+' · Ready';
}
function newInfra() {
  let seed=crypto.getRandomValues(new Uint32Array(1))[0] || 1;
  if(seed===estate.seed) seed=seed%4294967295+1;
  document.getElementById('seed').value=seed;
  gangId=nextGang(); infrastructureNumber++;
  generate();
}
ready.then(()=>{
  const saved=sessionStorage.getItem('wire-comparison-estate');
  if(saved){estate=JSON.parse(saved);document.getElementById('seed').value=estate.seed;prepare();status.textContent=describe()+' · Ready';}
  else generate();
  document.getElementById('run').disabled=false;
  document.getElementById('new').onclick=newInfra;
  document.getElementById('seed').onchange=generate;
  document.getElementById('seed').onkeydown=event=>{if(event.key==='Enter')generate();};
  document.getElementById('run').onclick=runBoth;
  document.querySelectorAll('[data-mode]').forEach(button=>button.onclick=()=>{
    mode=button.dataset.mode;document.querySelectorAll('[data-mode]').forEach(b=>b.classList.toggle('selected',b===button));
    prepare();status.textContent=describe()+' · Ready';
  });
  window.addEventListener('resize',fit);
});
document.getElementById('single').onclick=()=>sessionStorage.setItem('wire-return-estate',JSON.stringify(estate));
document.getElementById('fullscreen').onclick=()=>document.fullscreenElement?document.exitFullscreen():document.documentElement.requestFullscreen();
