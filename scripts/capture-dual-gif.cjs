const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH||'playwright-core');
const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const mode=process.env.DUAL_MODE||'baseline';
const output=path.resolve(__dirname,mode==='baseline'?'../../.gif_capture_dual':`../../.gif_capture_dual_${mode}`);fs.mkdirSync(output,{recursive:true});
(async()=>{const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
try{const page=await browser.newPage({viewport:{width:2880,height:1620},deviceScaleFactor:1});const errors=[];page.on('pageerror',e=>errors.push(e.message));
await page.goto(process.env.DUAL_URL||'http://localhost:8080/dual.html');await page.waitForFunction(()=>!document.getElementById('run').disabled);
await page.selectOption('#duration','30');
await page.click(`[data-mode="${mode}"]`);
const data=await page.evaluate(()=>{const end=prepare();const states=frames.map(f=>f.contentWindow.comparison.state());return {end,estates:states.map(s=>s.estate),lanes:states.map(s=>s.lanes)};});
assert.deepEqual(data.estates[0],data.estates[1]);assert.equal(data.estates[0].assets.length,54);assert.deepEqual(data.lanes,[1,3]);
for(let i=0;i<=145;i++){
 await page.evaluate(({i,end})=>{frames.forEach(f=>f.contentWindow.comparison.advance(end*i/145));status.textContent=describe()+(i===145?' · Both complete':'');},{i,end:data.end});
 await page.screenshot({path:path.join(output,`${String(i).padStart(3,'0')}.png`)});
 if(i%25===0)console.log(`Captured ${i}/145`);
}
assert.deepEqual(errors,[]);assert(await page.evaluate(()=>frames.every(f=>f.contentWindow.comparison.state().done)));
fs.writeFileSync(path.join(output,'manifest.json'),JSON.stringify({frames:146,seed:data.estates[0].seed,assets:54,mode,durationMs:30000,end:data.end},null,2));
}finally{await browser.close();}})().catch(e=>{console.error(e);process.exitCode=1});
