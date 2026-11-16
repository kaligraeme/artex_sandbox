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
    fs.readFile(file,(err,data)=>{res.statusCode=err?404:200;res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':file.endsWith('.html')?'text/html':'application/octet-stream');res.end(err?'missing':data);});
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
    const page=await browser.newPage({viewport:{width:1440,height:900}});
    const errors=[];page.on('pageerror',err=>errors.push(err.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.waitForURL('**/wire.html');await page.waitForSelector('.node');
    assert.equal(await page.locator('.mode-btn').count(),4);
    assert.equal(await page.locator('[data-mode="canaries"], [data-mode="soc-canary"], select').count(),0);
    if(process.env.REMEDIATION_SCREENSHOT){
      await page.evaluate(()=>{estate=generateEstate({preset:'demo',seed:777,seedExercise:true});referenceCase=null;catalogLabel.hidden=true;playRun();finishRun();});
      await page.waitForTimeout(250); // Allow the 200 ms state-color transition to settle for visual assertions.
      const cues=await page.evaluate(()=>[...document.querySelectorAll('.node.hit')].map(n=>({color:getComputedStyle(n.querySelector('.node-icon')).backgroundColor,labelTop:n.querySelector('.node-label').getBoundingClientRect().top,haloBottom:n.querySelector('.node-halo').getBoundingClientRect().bottom})));
      assert(cues.length>0);
      for(const cue of cues){assert.equal(cue.color,'rgb(216, 91, 123)');assert(cue.labelTop>=cue.haloBottom,'Attack halo must not cover its label');}
      await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT.replace('.png','-baseline.png')});
    }
    for(const viewport of [{width:1440,height:900},{width:1280,height:720},{width:390,height:844}]){
      await page.setViewportSize(viewport);
      for(const seed of [1,42,99]){
        await page.evaluate(seed=>{estate=generateEstate({seed,seedExercise:true});referenceCase=null;catalogLabel.hidden=true;pre2023Group='lockbit';playRun();finishRun();},seed);
        const collisions=await page.evaluate(()=>{
          const boxes=[...document.querySelectorAll('.node-label')].map(n=>({id:n.parentElement.id,r:n.getBoundingClientRect()}));
          return boxes.flatMap((a,i)=>boxes.slice(i+1).filter(b=>a.r.left<b.r.right&&a.r.right>b.r.left&&a.r.top<b.r.bottom&&a.r.bottom>b.r.top).map(b=>[a.id,b.id]));
        });
        assert.deepEqual(collisions,[],`labels overlap: ${viewport.width}, seed ${seed}`);
        const before=await page.evaluate(()=>JSON.stringify(estate));
        for(const attacker of ['pre2023','artex']){
          await page.click(`[data-attacker="${attacker}"]`);
          assert.equal(await page.locator(`[data-attacker="${attacker}"]`).getAttribute('aria-pressed'),'true');
          assert.equal(await page.locator('.attacker-marker').count(),attacker==='artex'?3:1);
          for(const mode of ['baseline','patch','soc','combined']){
            await page.click(`[data-mode="${mode}"]`);
            if(mode==='combined') {
              const deployed=await page.evaluate(()=>estate.defensePosture.decoys.length);
              assert(deployed>0,'Generated estate must deploy a canary');
              assert.equal(await page.locator('.node.decoy .canary-marker').count(),deployed,'Canary deployment must be visible before Results');
            }
            await page.click('#map-results-btn');
            const snapshot=await page.evaluate(()=>({run:JSON.stringify(run),style:runHud.className,expected:run.result.style,text:runHud.textContent,label:run.result.label}));
            assert.equal(snapshot.style,snapshot.expected);assert(snapshot.text.includes(snapshot.label));
            const overlaps=await page.evaluate(()=>{
              const boxes=[...document.querySelectorAll('.node-label, .node-kev')].filter(n=>getComputedStyle(n).display!=='none').map(n=>({id:n.parentElement.id,r:n.getBoundingClientRect()}));
              return boxes.flatMap((a,i)=>boxes.slice(i+1).filter(b=>a.id!==b.id&&a.r.left<b.r.right&&a.r.right>b.r.left&&a.r.top<b.r.bottom&&a.r.bottom>b.r.top).map(b=>[a.id,b.id]));
            });
            assert.deepEqual(overlaps,[],`active callout collision: ${viewport.width}/${seed}/${attacker}/${mode}`);
            await page.click('#map-replay-btn');await page.click('#map-results-btn');
            assert.equal(await page.evaluate(()=>JSON.stringify(run)),snapshot.run);
            assert.equal(await page.evaluate(()=>JSON.stringify(estate)),before);
          }
        }
        await page.locator('.node').first().focus();
        assert((await page.locator('#asset-details').textContent()).length>20);
        await page.click('#search-toggle');
        const label=await page.locator('.node-label').first().textContent();
        await page.fill('#asset-search',label);
        assert(await page.locator('.node.search-match').count()>0);
        assert.equal(await page.evaluate(()=>JSON.stringify(estate)),before);
        await page.fill('#asset-search','definitely-not-an-enterprise-asset');
        assert.equal(await page.locator('.node.search-match').count(),0);
        await page.press('#asset-search','Escape');
        assert.equal(await page.locator('#search-toggle').getAttribute('aria-expanded'),'false');
        await page.evaluate(()=>window.scrollTo(0,0));
        if(viewport.width===1440 && seed===1 && process.env.REMEDIATION_SCREENSHOT) await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT.replace('.png','-desktop.png')});
        console.log(`PASS browser ${viewport.width}x${viewport.height}, seed ${seed}: layout, 8 combinations, replay, details`);
      }
    }
    await page.evaluate(()=>{
      estate=generateEstate({preset:'demo',seed:404,seedExercise:false});
      estate.findings=[];estate.credentials=[];referenceCase=null;catalogLabel.hidden=true;playRun();finishRun();
    });
    const neutral=await page.evaluate(()=>({label:run.result.label,style:runHud.className,text:runHud.textContent}));
    assert.equal(neutral.label,'No protected read established');
    assert.equal(neutral.style,'');
    assert(neutral.text.includes(neutral.label),'Neutral result must be rendered from classifyRun');
    const previous=await page.evaluate(()=>JSON.stringify(estate));
    await page.click('#new-run-btn');
    assert.notEqual(await page.evaluate(()=>JSON.stringify(estate)),previous);
    await page.click('#map-results-btn');
    await page.locator('[data-attacker="artex"]').focus();await page.keyboard.press('Enter');
    assert.equal(await page.locator('[data-attacker="artex"]').getAttribute('aria-pressed'),'true');
    await page.click('#map-replay-btn');
    await page.waitForTimeout(1600);
    assert(await page.evaluate(()=>phaseIndex>0),'Animation must advance its event history');
    await page.click('#map-results-btn');
    await page.emulateMedia({reducedMotion:'reduce'});
    assert.equal(await page.locator('.node-halo').first().evaluate(n=>getComputedStyle(n).animationName),'none');
    assert.deepEqual(errors,[]);
    if(process.env.REMEDIATION_SCREENSHOT) await page.screenshot({path:process.env.REMEDIATION_SCREENSHOT});
    console.log('PASS browser: New Infra, redirect, console; no label collisions or replay drift');
  }finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
}
main().catch(err=>{console.error(err);process.exitCode=1;});
