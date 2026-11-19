const {chromium}=require('../.capture_deps/node_modules/playwright-core');
const fs=require('fs'),path=require('path'),http=require('http'),assert=require('assert');
const root=path.resolve(__dirname), output=path.resolve(root,'../.gif_capture_path_final');fs.mkdirSync(output,{recursive:true});
const server=http.createServer((req,res)=>{let f=path.resolve(root,'.'+decodeURIComponent(req.url.split('?')[0]));if(!f.startsWith(root+path.sep)){res.writeHead(403);return res.end();}fs.readFile(f,(e,d)=>{res.statusCode=e?404:200;res.setHeader('Content-Type',f.endsWith('.css')?'text/css':f.endsWith('.js')?'text/javascript':f.endsWith('.html')?'text/html':f.endsWith('.svg')?'image/svg+xml':'application/octet-stream');res.end(e?'missing':d);});});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});try{
const page=await browser.newPage({viewport:{width:1360,height:900}});const errors=[];page.on('pageerror',e=>errors.push(e.stack));const url=`http://127.0.0.1:${server.address().port}`;
await page.goto(url+'/wire.html?capture=path');await page.waitForFunction(()=>window.pathCapture);
const manifest=[];let frameNumber=0;
for(const [index,seed] of [1853,2468,3579].entries()){
const info=await page.evaluate(({seed,index})=>pathCapture.prepare(WireEngine.generateEstate({preset:'mixed',seed,seedExercise:true}),'artex','baseline',`Infrastructure ${index+1} / 3`),{seed,index});
await page.setViewportSize({width:1360,height:info.height});
const expected=require('./js/wire-engine.js');const full=expected.simulateWireRun(expected.generateEstate({preset:'mixed',seed,seedExercise:true}),'baseline','artex');
const state=await page.evaluate(()=>pathCapture.state());fs.writeFileSync(path.join(output,'parity.json'),JSON.stringify({actual:state.events,expected:full.events},null,2));assert.equal(JSON.stringify(state.events),JSON.stringify(full.events));assert(state.ids.length<full.events.length);assert.equal(state.lanes,3);
const positions=[];
for(let i=0;i<=120;i++){
await page.evaluate(time=>pathCapture.advance(time),info.end*i/120);
const check=await page.evaluate(()=>{const bounds=document.getElementById('viewport').getBoundingClientRect();return {nodes:[...document.querySelectorAll('.node')].map(n=>({id:n.id,rect:n.getBoundingClientRect().toJSON()})),markers:[...document.querySelectorAll('.attacker-marker')].map(n=>({hidden:n.hidden,left:n.style.left,top:n.style.top})),bounds:bounds.toJSON()};});
assert.equal(check.nodes.length,state.ids.length);assert.equal(check.markers.length,3);assert(check.markers.every(m=>!m.hidden));
for(const n of check.nodes){assert(n.rect.x>=0&&n.rect.right<=1360,`horizontal clip ${n.id}`);assert(n.rect.bottom<=info.height,`vertical clip ${n.id}`);const badge=await page.locator('#'+n.id+' .node-kev').boundingBox();if(badge)assert(badge.y+badge.height<=info.height,'badge clip '+n.id);}
positions.push(JSON.stringify(check.markers));
await page.screenshot({path:path.join(output,`${String(frameNumber++).padStart(3,'0')}.png`)});
}
assert(new Set(positions).size>10,'agents must move');const final=await page.evaluate(()=>pathCapture.state());assert(final.done);assert.equal(final.time,info.end);manifest.push({seed,assets:state.ids.length,end:info.end,height:info.height,frames:121});console.log(JSON.stringify(manifest.at(-1)));
}
// Verify the control-bearing interactive view remains available.
await page.goto(url+'/wire.html');await page.waitForSelector('.node');assert(await page.locator('[data-mode="combined"]').isVisible());assert.deepEqual(errors,[]);
fs.writeFileSync(path.join(output,'manifest.json'),JSON.stringify(manifest,null,2));console.log('PASS: event parity, pruning, bounds, three moving agents, clocks, completion, normal UI');
}finally{await browser.close();server.close();}})().catch(e=>{console.error(e);process.exitCode=1;server.close();});