const {chromium}=require(process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
async function main(){
  const server=http.createServer((req,res)=>{
    const file=path.join(root,decodeURIComponent(req.url.split('?')[0]));
    if(!file.startsWith(root+path.sep)){res.writeHead(403);res.end();return;}
    fs.readFile(file,(err,data)=>{res.statusCode=err?404:200;res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':'text/html');res.end(err?'missing':data);});
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;
  try{
    browser=await chromium.launch({headless:true,executablePath:process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
    const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    const base=`http://127.0.0.1:${server.address().port}`;
    await page.goto(`${base}/dual.html`);
    await page.waitForFunction(()=>!document.getElementById('run').disabled);
    const panels=page.frames().filter(frame=>frame.url().includes('wire.html'));
    assert.equal(panels.length,2);
    const before=[];
    for(const panel of panels){
      const initial=await panel.evaluate(()=>({estate:JSON.stringify(estate),run:JSON.stringify(run),
        visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),initial:discoveryPlan.initialAssetIds,
        positions:Object.fromEntries([...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>[n.id,[n.x,n.y]]))}));
      assert.deepEqual(initial.visible,initial.initial);before.push(initial);
    }
    assert.deepEqual(before[0].visible,before[1].visible,'Both attackers have identical starting infrastructure');
    assert.deepEqual(before[0].positions,before[1].positions,'Shared starting infrastructure has identical positions');
    await page.click('#run');await page.waitForTimeout(1200);
    assert(await page.evaluate(()=>fittedHeights===frames.map(f=>f.contentWindow.comparison.height()).join(',')),'Embedded frames fit the growing views');
    await page.evaluate(()=>{cancelAnimationFrame(animation);frames.forEach(f=>f.contentWindow.comparison.advance(Infinity));fit();});
    for(const [i,panel] of panels.entries()){
      const final=await panel.evaluate(()=>({estate:JSON.stringify(estate),run:JSON.stringify(run),
        visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),expected:discoveryPlan.assetIds}));
      assert.deepEqual(final.visible,final.expected);assert.equal(final.estate,before[i].estate);assert.equal(final.run,before[i].run);
    }
    // New Infra must update the displayed seed and actual profile, not merely replay.
    let previousSeed=1853, previousGang='lockbit';
    const gangs=new Set([previousGang]);
    for(let i=0;i<4;i++){
      await page.click('#new');
      const current=await page.evaluate(()=>({seed:estate.seed,field:Number(document.getElementById('seed').value),
        status:status.textContent,gang:gangId,label:document.getElementById('gang-profile').textContent,
        estates:frames.map(f=>JSON.stringify(f.contentWindow.comparison.state().estate))}));
      assert.notEqual(current.seed,previousSeed);assert.equal(current.field,current.seed);
      assert(current.status.includes(`Seed ${current.seed}`));assert.notEqual(current.gang,previousGang);
      assert.equal(current.estates[0],current.estates[1]);assert.notEqual(current.estates[0],before[0].estate);
      const actual=await panels[0].evaluate(()=>({gang:run.assumptions.techniquePolicy.gangId,label:pre2023Groups[pre2023Group],infra:infrastructureNumber}));
      assert.equal(actual.gang,current.gang);assert(current.label.includes(actual.label));assert.equal(actual.infra,i+2);
      gangs.add(current.gang);previousSeed=current.seed;previousGang=current.gang;
    }
    assert.equal(gangs.size,5,'New infrastructure cycles through all five gang policies');
    const scenario=await page.evaluate(()=>({estate:JSON.stringify(estate),gang:gangId}));
    for(const selector of ['[data-mode="patch"]','#run','[data-mode="baseline"]']){
      await page.click(selector);
      assert.deepEqual(await page.evaluate(()=>({estate:JSON.stringify(estate),gang:gangId})),scenario);
      assert.equal(await panels[0].evaluate(()=>run.assumptions.techniquePolicy.gangId),scenario.gang);
    }
    await page.fill('#seed','1853');await page.press('#seed','Enter');
    assert.equal(await panels[0].evaluate(()=>JSON.stringify(estate)),before[0].estate,'Explicit seed reproduces the estate');
    await page.fill('#seed','4294967296');await page.press('#seed','Enter');
    assert.match(await page.locator('#status').textContent(),/Enter an integer seed/);
    assert.equal(await panels[0].evaluate(()=>JSON.stringify(estate)),before[0].estate,'Invalid seed leaves the current estate intact');
    await page.evaluate(()=>{gangId='revil';document.getElementById('seed').value=1;generate();
      estate.assets.find(a=>a.id==='windows-desktop').conditions.mailFilterBlocksAttachment=true;prepare();});
    assert.equal(await panels[0].evaluate(()=>comparison.done),false,'Ready view has not run');
    await page.click('#run');
    const failedEntry=await panels[0].evaluate(()=>({done:comparison.done,time:modeledTime,hud:runHud.textContent,
      successes:run.events.filter(e=>e.outcome==='succeeded').length}));
    assert.equal(failedEntry.done,true,'Zero-duration REvil run completes on explicit start');
    assert.equal(failedEntry.time,0);assert.equal(failedEntry.successes,0);
    assert.match(failedEntry.hud,/REvil.*No access established.*Mail filtering blocks/);
    await page.evaluate(()=>{document.getElementById('seed').value=3;generate();});
    await page.click('#run');
    await panels[0].evaluate(()=>comparison.advance(Infinity));
    const successfulEntry=await panels[0].evaluate(()=>({done:comparison.done,events:run.events.filter(e=>e.outcome==='succeeded').map(e=>e.technique)}));
    assert(successfulEntry.done);assert(successfulEntry.events.includes('T1566.001'));assert(successfulEntry.events.includes('T1047'));assert(successfulEntry.events.includes('T1486'));
    for(const gang of ['conti','revil']){
      await page.evaluate(gang=>{gangId=gang;estate=WireEngine.generateEstate({seed:1,seedExercise:true});
        estate.findings=estate.findings.filter(f=>f.kind==='phishing_attachment');estate.credentials=[];runBoth();},gang);
      const phish=await panels[0].evaluate(()=>({done:comparison.done,state:currentNodes.get('windows-desktop').el.querySelector('.node-state').textContent,
        tickets:[...socTickets.values()],impact:run.result.impact}));
      assert.equal(phish.state,'PHISH EXECUTED');assert.equal(phish.impact,false);
      assert(phish.tickets.some(t=>t.title.includes('Phishing attachment executed')&&t.severity==='HIGH'),`${gang} phishing alert appears without lateral movement`);
      assert(await panels[0].evaluate(()=>{comparison.advance(Infinity);return comparison.done;}),`${gang} isolated phish completes`);
    }
    await page.evaluate(()=>{estate.findings=[];estate.credentials=[];runBoth();});
    assert(await page.evaluate(()=>frames.every(f=>f.contentWindow.comparison.done)),'Both zero-duration runs complete');
    assert.match(await page.locator('#status').textContent(),/Both complete/);
    await page.goto(`${base}/wire.html?capture=path&manual=1`);
    await page.waitForFunction(()=>!!window.pathCapture);
    const pathStart=await page.evaluate(()=>{
      pathCapture.prepare(WireEngine.generateEstate({seed:3,seedExercise:true}),'pre2023','baseline');
      return {estate:JSON.stringify(estate),run:JSON.stringify(run),visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),initial:discoveryPlan.initialAssetIds};
    });
    assert.deepEqual(pathStart.visible,pathStart.initial);
    const pathEnd=await page.evaluate(()=>{
      pathCapture.advance(Infinity);
      return {estate:JSON.stringify(estate),run:JSON.stringify(run),visible:[...currentNodes.values()].filter(n=>!n.el.hidden).map(n=>n.id),expected:discoveryPlan.assetIds};
    });
    assert.deepEqual(pathEnd.visible,pathEnd.expected);assert.equal(pathEnd.estate,pathStart.estate);assert.equal(pathEnd.run,pathStart.run);
    assert.deepEqual(errors,[]);
    console.log('PASS comparison discovery: shared initial view, growing fit, trace filtering, fresh seeds, gang rotation, stable replay/defenses, explicit seed reproduction');
  }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
