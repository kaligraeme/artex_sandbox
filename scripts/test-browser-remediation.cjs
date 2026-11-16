// Set PLAYWRIGHT_CORE_PATH and optionally EDGE_PATH when Playwright is installed outside this repo.
const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
async function main(){
  const server=http.createServer((req,res)=>{
    const requested=decodeURIComponent(req.url.split('?')[0]);
    const file=path.join(root,requested==='/'?'index.html':requested);
    if(!file.startsWith(root+path.sep)){res.writeHead(403);res.end();return;}
    fs.readFile(file,(err,data)=>{res.statusCode=err?404:200;res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.json')?'application/json':file.endsWith('.html')?'text/html':'application/octet-stream');res.end(err?'missing':data);});
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
    const page=await browser.newPage({viewport:{width:1440,height:900}});
    const errors=[];page.on('pageerror',err=>errors.push(err.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.waitForURL('**/wire.html');await page.waitForSelector('.node');
    for(const viewport of [{width:1440,height:900},{width:1280,height:720},{width:390,height:844}]){
      await page.setViewportSize(viewport);
      for(const seed of [1,42,99]){
        await page.evaluate(seed=>{estate=generateEstate({seed,seedExercise:true});referenceCase=null;pre2023Group='lockbit';playRun();finishRun();},seed);
        const collisions=await page.evaluate(()=>{
          const boxes=[...document.querySelectorAll('.node-label')].map(n=>({id:n.parentElement.id,r:n.getBoundingClientRect()}));
          return boxes.flatMap((a,i)=>boxes.slice(i+1).filter(b=>a.r.left<b.r.right&&a.r.right>b.r.left&&a.r.top<b.r.bottom&&a.r.bottom>b.r.top).map(b=>[a.id,b.id]));
        });
        assert.deepEqual(collisions,[],`labels overlap: ${viewport.width}, seed ${seed}`);
        const before=await page.evaluate(()=>JSON.stringify(estate));
        for(const attacker of ['pre2023','artex']){
          await page.selectOption('#map-profile',attacker);
          for(const mode of ['baseline','patch','canaries','soc','soc-canary','combined']){
            await page.click(`[data-mode="${mode}"]`);await page.click('#map-results-btn');
            const snapshot=await page.evaluate(()=>({run:JSON.stringify(run),style:runHud.className,expected:run.result.style,text:runHud.textContent,label:run.result.label}));
            assert.equal(snapshot.style,snapshot.expected);assert(snapshot.text.includes(snapshot.label));
            await page.click('#map-replay-btn');await page.click('#map-results-btn');
            assert.equal(await page.evaluate(()=>JSON.stringify(run)),snapshot.run);
            assert.equal(await page.evaluate(()=>JSON.stringify(estate)),before);
          }
        }
        await page.locator('.node').first().focus();
        assert((await page.locator('#asset-details').textContent()).length>20);
        await page.evaluate(()=>window.scrollTo(0,0));
        if(viewport.width===1440 && seed===1 && process.env.REMEDIATION_SCREENSHOT) await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT.replace('.png','-desktop.png')});
        console.log(`PASS browser ${viewport.width}x${viewport.height}, seed ${seed}: layout, 12 combinations, replay, details`);
      }
    }
    const previous=await page.evaluate(()=>JSON.stringify(estate));
    await page.click('#new-run-btn');
    assert.notEqual(await page.evaluate(()=>JSON.stringify(estate)),previous);
    await page.click('#map-results-btn');
    assert.deepEqual(errors,[]);
    if(process.env.REMEDIATION_SCREENSHOT) await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT});
    console.log('PASS browser: New Infra, redirect, console; no label collisions or replay drift');
  }finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
}
main().catch(err=>{console.error(err);process.exitCode=1;});
