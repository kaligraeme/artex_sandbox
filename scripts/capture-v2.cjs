// Event-driven screen capture of the actual Wire renderer. No engine or scenario outcomes are changed.
const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const output=path.resolve(process.env.V2_FRAMES || path.join(root,'..','.gif_capture_v2'));
const engine=require('../js/wire-engine.js');
const sourceEstate=engine.generateEstate({preset:'mixed',seed:1853,seedExercise:true});
const modes=['baseline','patch','soc','combined'];
const labels={baseline:'Baseline',patch:'Virtual Patch',soc:'Agentic SOAR',combined:'Defense-in-Depth'};
// A focused, valid enterprise slice keeps concurrent actors and all meaningful branches in view.
// Re-simulate the resulting estate: do not reuse outcomes or timings from the larger source graph.
const retained=new Set();
for(const actor of ['artex','lockbit'])for(const mode of modes){
  const result=engine.simulateWireRun(sourceEstate,mode,actor);
  for(const event of result.events.filter(e=>['succeeded','blocked'].includes(e.outcome))){retained.add(event.targetId);if(event.sourceId)retained.add(event.sourceId);}
  for(const control of result.controls)retained.add(control.targetId);
}
for(const credential of sourceEstate.credentials)if(retained.has(credential.sourceAssetId))for(const id of credential.targetAssetIds || [])retained.add(id);
const focusedEstate={...sourceEstate,assets:sourceEstate.assets.filter(a=>retained.has(a.id)),findings:sourceEstate.findings.filter(f=>retained.has(f.assetId)),
  relationships:sourceEstate.relationships.filter(r=>retained.has(r.sourceId)&&retained.has(r.targetId)),credentials:sourceEstate.credentials.filter(c=>retained.has(c.sourceAssetId)),
  actionOrder:sourceEstate.actionOrder.filter(id=>retained.has(id)),defensePosture:{...sourceEstate.defensePosture,decoys:sourceEstate.defensePosture.decoys.filter(d=>retained.has(d.assetId))}};
const estate=process.env.V2_FOCUSED==='1'?focusedEstate:sourceEstate;
assert(engine.validateEstate(estate).valid);
async function main(){
  fs.mkdirSync(output,{recursive:true});
  const manifest={title:'ARTEX vs Pre-LLM Attacks — v2',preset:'mixed',seed:1853,viewport:{width:1440,height:1060},
    note:`${estate.assets.length}-asset enterprise from generated seed 1853. All assets visible from the start; fixed overview across runs. Actual engine events; accelerated event-driven playback. Model times are not recording time or measured field performance.`,
    frames:[],runs:[],estate};
  const server=http.createServer((req,res)=>{
    const url=decodeURIComponent(req.url.split('?')[0]);const file=path.join(root,url==='/'?'index.html':url);
    if(!file.startsWith(root+path.sep)){res.writeHead(403);res.end();return;}
    fs.readFile(file,(err,data)=>{res.statusCode=err?404:200;res.setHeader('Content-Type',file.endsWith('.css')?'text/css':file.endsWith('.js')?'text/javascript':file.endsWith('.json')?'application/json':file.endsWith('.html')?'text/html':'application/octet-stream');res.end(err?'missing':data);});
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
    const page=await browser.newPage({viewport:manifest.viewport,deviceScaleFactor:1});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/wire.html`);await page.waitForSelector('.node');
    await page.evaluate(example=>{
      cancelAnimationFrame(frame);estate=example;referenceCase=null;pre2023Group='lockbit';infrastructureNumber=1;runNumber=0;resetGraph();
      const caption=document.createElement('div');caption.id='capture-caption';document.body.appendChild(caption);
      const cover=document.createElement('section');cover.id='capture-cover';document.body.appendChild(cover);
    },estate);
    const overviewHeight=await page.evaluate(()=>Math.ceil(Math.max(...[...currentNodes.values()].map(n=>n.y))+document.querySelector('.top-bar').getBoundingClientRect().height+350));
    manifest.viewport.height=Math.max(1060,overviewHeight);
    await page.setViewportSize(manifest.viewport);
    await page.addStyleTag({content:`
      .soc-ticker{bottom:125px} #asset-details{display:none}
      #capture-caption{position:fixed;bottom:15px;left:20px;right:20px;z-index:3000;background:#101d29f5;border:1px solid #55798b;border-radius:8px;padding:12px 18px;color:#dce6ee;font:14px/1.6 'Segoe UI',Arial;box-shadow:0 10px 30px #0005}
      #capture-caption strong{color:#73e4f4;font-size:17px} #capture-caption .note{float:right;color:#92aabd;font-size:12px}
      #capture-cover{position:fixed;inset:250px 160px auto;z-index:4000;padding:40px;background:#101d29f5;border:1px solid #517889;border-radius:12px;color:#dce6ee;box-shadow:0 20px 100px #0008;font:18px/1.7 'Segoe UI',Arial}
      #capture-cover h1{color:#73e4f4;font-size:36px;margin-bottom:12px} #capture-cover p{color:#b7c9d7;margin:12px 0} #capture-cover small{color:#8fa6ba;font-size:14px}
      #capture-cover table{width:100%;border-collapse:collapse;font-size:16px;margin:20px 0} #capture-cover th,#capture-cover td{text-align:left;padding:13px;border-bottom:1px solid #31495c} #capture-cover th{color:#73e4f4}
    `});
    const snap=async(duration,label)=>{
      const name=`${String(manifest.frames.length).padStart(4,'0')}.png`;
      await page.screenshot({path:path.join(output,name)});manifest.frames.push({file:name,durationMs:duration,label});
    };
    await page.evaluate(()=>{
      document.getElementById('capture-caption').innerHTML='<strong>V2 · ARTEX vs Pre-LLM Attacks</strong><span class="note">Modeled timelines · Accelerated playback</span><br>One enterprise · Four defenses · Eight complete event replays';
      document.getElementById('capture-cover').innerHTML='<h1>ARTEX vs Pre-LLM Attacks</h1><p>The same enterprise. The same weaknesses.<br>Four defenses, compared one at a time.</p><p>Baseline → Virtual Patch → Agentic SOAR → Defense-in-Depth</p><small>Each chapter shows ARTEX, then a Pre-LLM / LockBit-style run.<br>Illustrative generated scenario · Seed 1853 · Historical-context clock with synthetic stage and response assumptions.</small>';
    });await snap(3200,'Introduction');
    for(const mode of modes)for(const actor of ['artex','pre2023']){
      await page.evaluate(({mode,actor})=>{
        document.getElementById('capture-cover').hidden=true;
        attackerChoice=actor;defense=mode;
        document.querySelectorAll('[data-attacker]').forEach(b=>{const selected=b.dataset.attacker===actor;b.classList.toggle('selected',selected);b.setAttribute('aria-pressed',String(selected));});
        document.querySelectorAll('[data-mode]').forEach(b=>{const selected=b.dataset.mode===mode;b.classList.toggle('selected',selected);b.setAttribute('aria-pressed',String(selected));});
        playRun();cancelAnimationFrame(frame);window.scrollTo(0,0);
      },{mode,actor});
      assert.equal(await page.locator('.attacker-marker').count(),actor==='artex'?3:1);
      const captured=await page.evaluate(()=>({events:run.events,controls:run.controls,summary:run.summary,result:run.result,assumptions:run.assumptions,phases:phases.map(p=>({time:p.time,events:p.events}))}));
      manifest.runs.push({mode,actor,...captured});
      const heading=`${modes.indexOf(mode)+1}/4 · ${labels[mode]} · ${actor==='artex'?'ARTEX':'Pre-LLM Attacks (LockBit-style)'}`;
      const caption=async(text)=>page.evaluate(({heading,text})=>{
        const box=document.getElementById('capture-caption');box.replaceChildren();
        const title=document.createElement('strong');title.textContent=heading;
        const note=document.createElement('span');note.className='note';note.textContent='Same infrastructure · Model time ≠ playback time';
        const detail=document.createElement('div');detail.textContent=text;box.append(title,note,detail);
      },{heading,text});
      await caption('Run begins · The stopwatch shows modeled elapsed time from the assumed foothold.');await page.waitForTimeout(250);await snap(1400,heading+' begins');
      let previousTime=0;
      for(let index=0;index<captured.phases.length;index++){
        const phase=captured.phases[index];
        const visible=phase.events.filter(e=>e.control||['succeeded','blocked','suppressed','alert_only'].includes(e.outcome));
        const focus=visible.find(e=>!e.control) || visible[0];
        if(visible.length){
          assert.equal(await page.locator('.node').count(),estate.assets.length);
          const names=visible.map(e=>{
            const asset=estate.assets.find(a=>a.id===e.targetId)?.label || e.targetId;
            const verb=e.control?({signal:'Alert received',decision:'Response approved',enforced:'Containment effective',failed:'Enforcement failed',denied:'Response lacks authority'}[e.control] || e.control)
              : e.outcome==='blocked'?'Virtual patch prevented access':e.outcome==='suppressed'?'Action suppressed by containment':e.grantedCapability==='data_read'?'Protected record read':e.grantedCapability==='decoy_alert'?'Canary touched':'Access established';
            return `${verb}: ${asset}${e.finding?.cveId?' · '+e.finding.cveId:''}`;
          });
          await caption(names.slice(0,2).join('  |  ')+(names.length>2?`  (+${names.length-2} other events)`:'')+'.');
          for(const fraction of [0.1,0.3,0.5,0.7,0.9]) {
            await page.evaluate(({phase,previousTime,fraction})=>{showTime(previousTime+(phase.time-previousTime)*fraction);},{phase,previousTime,fraction});
            await page.waitForTimeout(60);await snap(160,heading+' agent motion');
          }
        }
        await page.evaluate(index=>{renderPhase(phases[index],true);showTime(phases[index].time);phaseIndex=index+1;},index);
        previousTime=phase.time;
        if(visible.length){await page.waitForTimeout(260);await snap(850,heading+' action');}
      }
      await page.evaluate(()=>finishRun());
      const read=captured.events.find(e=>e.isProtectedRead&&e.outcome==='succeeded');
      await caption(`${captured.result.label}${read?` · First protected read at ${Math.floor(read.timeSec/60)} modeled minutes`:''}. ${captured.summary.blockedTransitions} prevented attempts · ${captured.summary.suppressedTransitions} suppressed effects.`);
      await snap(2200,heading+' result');
      assert.equal(await page.evaluate(()=>JSON.stringify(estate)),JSON.stringify(estate));
      console.log(`${heading}: ${captured.result.label}`);
    }
    const rows=modes.map(mode=>({label:labels[mode],values:['artex','pre2023'].map(actor=>{
      const r=manifest.runs.find(r=>r.mode===mode&&r.actor===actor);const read=r.events.find(e=>e.isProtectedRead&&e.outcome==='succeeded');
      return read?`Read at ${Math.floor(read.timeSec/60)} min${r.controls.some(c=>c.control==='enforced'&&c.timeSec>read.timeSec)?'; later containment':''}`:r.result.label;
    })}));
    await page.evaluate(rows=>{
      window.scrollTo(0,0);const cover=document.getElementById('capture-cover');cover.hidden=false;
      cover.innerHTML='<h1>Four defenses · Same enterprise</h1><table><thead><tr><th>Defense</th><th>ARTEX</th><th>Pre-LLM</th></tr></thead><tbody></tbody></table><small>These are outcomes for one selected illustrative scenario, not product effectiveness estimates.<br>Clock: modeled elapsed time · Playback accelerated · Full control stack = WAF + SOC + Canary</small>';
      for(const row of rows){const tr=document.createElement('tr');for(const value of [row.label,...row.values]){const td=document.createElement('td');td.textContent=value;tr.appendChild(td);}cover.querySelector('tbody').appendChild(tr);}
      document.getElementById('capture-caption').innerHTML='<strong>V2 · Comparison complete</strong><br>Same topology, weaknesses, sensor coverage and response assumptions across each pair.';
    },rows);await snap(6500,'Comparison summary');
    assert.deepEqual(errors,[]);fs.writeFileSync(path.join(output,'manifest.json'),JSON.stringify(manifest,null,2));
    console.log(`Captured ${manifest.frames.length} frames: ${output}`);
  }finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
