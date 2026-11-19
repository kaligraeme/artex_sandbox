const {chromium}=require('../.capture_deps/node_modules/playwright-core');
const fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert');
const root=path.resolve(__dirname), output=path.resolve(root,'../.gif_capture_stacked_attempts');fs.mkdirSync(output,{recursive:true});
const server=http.createServer((req,res)=>{let f=path.resolve(root,'.'+decodeURIComponent(req.url.split('?')[0]));if(!f.startsWith(root+path.sep)){res.writeHead(403);return res.end();}fs.readFile(f,(e,d)=>{res.statusCode=e?404:200;res.setHeader('Content-Type',f.endsWith('.css')?'text/css':f.endsWith('.js')?'text/javascript':f.endsWith('.html')?'text/html':f.endsWith('.svg')?'image/svg+xml':'application/octet-stream');res.end(e?'missing':d);});});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});try{
const page=await browser.newPage({viewport:{width:1760,height:1800}});const errors=[];page.on('pageerror',e=>errors.push(e.stack));const url=`http://127.0.0.1:${server.address().port}`;
await page.goto(url+'/path-comparison.html?manual=1');await page.waitForFunction(()=>window.pathComparison?.info);
const engine=require('./js/wire-engine.js'),planner=require('./js/capture-plan.js');
assert.equal(planner.clock(5580),'1h:33m');assert.equal(planner.clock(0),'0h:00m');assert.equal(planner.clock(36000),'10h:00m');
const manifest=[];let frameNumber=0;
for(const [index,seed] of [1853,2468,3579].entries()){
const info=await page.evaluate(({seed,index})=>pathComparison.prepare(seed,`Infrastructure ${index+1} / 3`),{seed,index});
await page.setViewportSize({width:1760,height:info.height});
const estate=engine.generateEstate({preset:'mixed',seed,seedExercise:true});const expected=['artex','lockbit'].map(actor=>engine.simulateWireRun(estate,'baseline',actor));const plan=planner.create(estate,expected);
let states=await page.evaluate(()=>pathComparison.state());
for(let panel=0;panel<2;panel++){
 assert.equal(JSON.stringify(states[panel].events),JSON.stringify(expected[panel].events));const comparable=e=>({...e,assets:e.assets.map(({x,y,...asset})=>asset)});assert.equal(JSON.stringify(comparable(states[panel].estate)),JSON.stringify(comparable(estate)));assert.equal(JSON.stringify(states[0].estate),JSON.stringify(states[1].estate));assert.deepEqual(states[panel].ids.sort(),[...plan.assetIds].sort());assert.equal(states[panel].lanes,panel?1:3);
 for(const event of expected[panel].events.filter(e=>e.outcome==='ineligible'&&e.timeSec>e.startSec))assert(states[panel].ids.includes(event.targetId),'failed branch removed');
}
const samples=[[],[]];let maxActive=0,maxSimultaneousMovement=0,failedRendered=false;
for(let i=0;i<=120;i++){
 const time=await page.evaluate(fraction=>{const time=pathComparison.timeAt(fraction);pathComparison.advance(time);return time;},i/120);
 const checks=await page.evaluate(()=>[...document.querySelectorAll('iframe')].map(f=>{const d=f.contentDocument,w=f.contentWindow;return {state:w.pathCapture.state(),nodes:[...d.querySelectorAll('.node')].map(n=>({id:n.id,x:n.style.left,y:n.style.top,rect:n.getBoundingClientRect().toJSON(),parts:[...n.querySelectorAll('.node-label,.node-kev,.node-state,.attempt-note')].filter(e=>e.getClientRects().length).map(e=>e.getBoundingClientRect().toJSON())})),markers:[...d.querySelectorAll('.attacker-marker')].map(n=>({hidden:n.hidden,working:n.classList.contains('working'),left:parseFloat(n.style.left),top:parseFloat(n.style.top)})),failed:d.querySelectorAll('.attempt-note').length,clock:d.querySelector('.capture-clock').textContent,clockSize:parseFloat(w.getComputedStyle(d.querySelector('.capture-clock')).fontSize),clockWeight:Number(w.getComputedStyle(d.querySelector('.capture-clock')).fontWeight),height:f.clientHeight};}));
 assert.deepEqual(checks[0].nodes.map(n=>[n.id,n.x,n.y]),checks[1].nodes.map(n=>[n.id,n.x,n.y]),'layout mismatch');
 for(const [panel,c] of checks.entries()){
  assert.equal(c.markers.length,panel?1:3);assert(c.markers.every(m=>!m.hidden));assert.equal(c.clock,planner.clock(Math.min(time,info.ends[panel])));assert(c.clockSize>=32&&c.clockWeight>=700);
  assert.equal(JSON.stringify(c.state.events),JSON.stringify(expected[panel].events));
  for(const n of c.nodes){assert(n.rect.x>=0&&n.rect.right<=1760,`node clipped ${n.id}`);for(const part of n.parts){assert(part.x>=0&&part.right<=1760&&part.bottom<=c.height,`label clipped ${n.id}`);}}
  const last=samples[panel].at(-1);if(panel===0){maxActive=Math.max(maxActive,c.markers.filter(m=>m.working).length);if(last)maxSimultaneousMovement=Math.max(maxSimultaneousMovement,c.markers.filter((m,k)=>m.working&&last[k].working&&Math.hypot(m.left-last[k].left,m.top-last[k].top)>1).length);}
  samples[panel].push(c.markers);failedRendered ||= c.failed>0;
 }
 await page.screenshot({path:path.join(output,`${String(frameNumber++).padStart(3,'0')}.png`)});
}
assert(failedRendered,'no unsuccessful branches rendered');assert(maxActive>=2,'no concurrency');assert(maxSimultaneousMovement>=2,'agents do not move concurrently');
states=await page.evaluate(()=>pathComparison.state());assert(states.every(s=>s.done));states.forEach((s,i)=>assert.equal(s.time,info.ends[i]));
manifest.push({seed,assets:plan.assetIds.length,height:info.height,ends:info.ends,frames:121,maxActive,maxSimultaneousMovement});console.log(JSON.stringify(manifest.at(-1)));
}
await page.goto(url+'/wire.html');await page.waitForSelector('.node');assert(await page.locator('[data-mode="combined"]').isVisible());assert.deepEqual(errors,[]);
fs.writeFileSync(path.join(output,'manifest.json'),JSON.stringify(manifest,null,2));console.log('PASS: full event parity, shared estate/layout/clock, failed attempts retained, bold clock format, real simultaneous agent movement, bounds, completion, normal UI');
}finally{await browser.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;server.close();});