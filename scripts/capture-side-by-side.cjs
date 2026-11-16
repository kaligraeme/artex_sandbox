const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core');
const fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert');
const root=path.resolve(__dirname,'..'), output=path.resolve(root,'..','.gif_capture_side_by_side');
const engine=require('../js/wire-engine.js');
const source=engine.generateEstate({preset:'mixed',seed:1853,seedExercise:true});
const retained=new Set();
for(const actor of ['artex','lockbit']) for(const mode of ['baseline','patch','soc','combined']) {
 const r=engine.simulateWireRun(source,mode,actor);
 for(const e of r.events.filter(e=>['succeeded','blocked'].includes(e.outcome))){retained.add(e.targetId);if(e.sourceId)retained.add(e.sourceId);}
 for(const c of r.controls)retained.add(c.targetId);
}
for(const c of source.credentials)if(retained.has(c.sourceAssetId))for(const id of c.targetAssetIds||[])retained.add(id);
const estate={...source,assets:source.assets.filter(a=>retained.has(a.id)),findings:source.findings.filter(f=>retained.has(f.assetId)),relationships:source.relationships.filter(r=>retained.has(r.sourceId)&&retained.has(r.targetId)),credentials:source.credentials.filter(c=>retained.has(c.sourceAssetId)),actionOrder:source.actionOrder.filter(id=>retained.has(id)),defensePosture:{...source.defensePosture,decoys:source.defensePosture.decoys.filter(d=>retained.has(d.assetId))}};
assert(engine.validateEstate(estate).valid);fs.mkdirSync(output,{recursive:true});
const server=http.createServer((req,res)=>{const f=path.join(root,decodeURIComponent(req.url.split('?')[0]));if(!f.startsWith(root+path.sep)){res.writeHead(403);return res.end();}fs.readFile(f,(e,d)=>{res.statusCode=e?404:200;res.setHeader('Content-Type',f.endsWith('.css')?'text/css':f.endsWith('.js')?'text/javascript':f.endsWith('.json')?'application/json':f.endsWith('.html')?'text/html':f.endsWith('.svg')?'image/svg+xml':f.endsWith('.png')?'image/png':'application/octet-stream');res.end(e?'missing':d);});});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));let browser;
try{browser=await chromium.launch({headless:true,executablePath:process.env.EDGE_PATH||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
const pages=[]; const runs=[];
for(const actor of ['pre2023','artex']){
 const p=await browser.newPage({viewport:{width:1440,height:1060},deviceScaleFactor:1});
 await p.goto(`http://127.0.0.1:${server.address().port}/wire.html`); await p.waitForSelector('.node');
 await p.addStyleTag({content:'.soc-ticker,#asset-details{display:none!important} * {transition:none!important}'});
 const data=await p.evaluate(({estate,actor})=>{cancelAnimationFrame(frame);estate && (window.__testEstate=estate); window.eval('estate = window.__testEstate'); referenceCase=null;catalogLabel.hidden=true;pre2023Group='lockbit';infrastructureNumber=1;runNumber=0;attackerChoice=actor;defense='baseline';document.querySelectorAll('[data-attacker]').forEach(b=>b.classList.toggle('selected',b.dataset.attacker===actor));document.querySelectorAll('[data-mode]').forEach(b=>b.classList.toggle('selected',b.dataset.mode==='baseline'));playRun();cancelAnimationFrame(frame);return {end:run.events.find(e=>e.isProtectedRead&&e.outcome==='succeeded').timeSec, lanes:run.lanes};},{estate,actor});
 assert.equal(data.lanes,actor==='artex'?3:1);pages.push(p);runs.push(data);
}
assert.equal(runs[0].end,16218);assert.equal(runs[1].end,3660);
const frames=121;
for(let i=0;i<frames;i++){
 const time=16218*i/(frames-1);
 for(let j=0;j<2;j++){
  await pages[j].evaluate(({time,end})=>{const current=Math.min(time,end);while(phaseIndex<phases.length&&phases[phaseIndex].time<=current){renderPhase(phases[phaseIndex],false);phaseIndex++;}showTime(current);if(time>=end){document.getElementById('run-status').classList.remove('running');document.getElementById('run-status').textContent='Baseline · Protected record read';runHud.textContent='Protected record read · Modeled elapsed time from assumed foothold';runHud.className='breached';}},{time,end:runs[j].end});
  await pages[j].screenshot({path:path.join(output,`${String(i).padStart(3,'0')}-${j}.png`)});
 }
 if(i%20===0)console.log(`Captured ${i}/${frames-1}`);
}
fs.writeFileSync(path.join(output,'manifest.json'),JSON.stringify({runs,frames,playbackSeconds:30,estateAssets:estate.assets.length},null,2));
}finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}})().catch(e=>{console.error(e);process.exitCode=1});
