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
    console.log('PASS comparison discovery: external-only start, growing iframe fit, complete trace filtering, focused path view, unchanged estates and events');
  }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
}
main().catch(error=>{console.error(error);process.exitCode=1;});
