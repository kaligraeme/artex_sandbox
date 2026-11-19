const panels=[...document.querySelectorAll('iframe')];
window.pathComparison={
  async ready(){await Promise.all(panels.map(p=>new Promise(resolve=>{if(p.contentWindow.pathCapture)return resolve();p.addEventListener('load',resolve,{once:true});})));},
  prepare(seed=1853,label='Infrastructure 1 / 3'){
    cancelAnimationFrame(this.animation);
    const estate=WireEngine.generateEstate({preset:'mixed',seed,seedExercise:true});
    const runs=['artex','lockbit'].map(actor=>WireEngine.simulateWireRun(estate,'baseline',actor));
    const plan=CapturePlan.create(estate,runs);
    const infos=panels.map((panel,i)=>panel.contentWindow.pathCapture.prepare(estate,i?'pre2023':'artex','baseline',label,plan));
    panels.forEach((panel,i)=>panel.style.height=`${infos[i].height}px`);
    document.getElementById('title').textContent=`${label} / Same infrastructure / BASELINE`;
    this.info={end:Math.max(...infos.map(i=>i.end)),artexEnd:infos[0].end,ends:infos.map(i=>i.end),height:Math.ceil(document.body.getBoundingClientRect().height),plan};
    return this.info;
  },
  advance(time){panels.forEach(p=>p.contentWindow.pathCapture.advance(time));},
  timeAt(fraction){
    // Give the concurrent ARTEX section screen time, then continue the same clock to the human finish.
    const {end,artexEnd}=this.info;
    if(end<=artexEnd)return end*fraction;
    return fraction<=.65?artexEnd*fraction/.65:artexEnd+(end-artexEnd)*(fraction-.65)/.35;
  },
  play(){const start=performance.now();const tick=now=>{const fraction=Math.min(1,(now-start)/40000);this.advance(this.timeAt(fraction));if(fraction<1)this.animation=requestAnimationFrame(tick);};this.animation=requestAnimationFrame(tick);},
  state(){return panels.map(p=>p.contentWindow.pathCapture.state());}
};
pathComparison.ready().then(()=>{pathComparison.prepare(Number(new URLSearchParams(location.search).get('seed'))||1853);if(!new URLSearchParams(location.search).has('manual'))pathComparison.play();});
