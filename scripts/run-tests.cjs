// Runs every scripts/test-*.cjs suite in sequence and fails if any suite fails.
// --headless-only skips the suites that drive a real browser through playwright-core.
const {spawnSync}=require('node:child_process');
const fs=require('node:fs');
const path=require('node:path');

const dir=__dirname;
const headlessOnly=process.argv.includes('--headless-only');
const suites=fs.readdirSync(dir).filter(name=>/^test-.*\.cjs$/.test(name)).sort();
const usesBrowser=name=>/playwright-core/.test(fs.readFileSync(path.join(dir,name),'utf8'));

const failed=[];
for(const name of suites){
  if(headlessOnly&&usesBrowser(name)){console.log(`SKIP ${name} (browser)`);continue;}
  const started=Date.now();
  const result=spawnSync(process.execPath,[path.join(dir,name)],{stdio:['ignore','pipe','pipe'],encoding:'utf8'});
  const seconds=((Date.now()-started)/1000).toFixed(1);
  if(result.status===0){
    const summary=result.stdout.trim().split('\n').pop();
    console.log(`ok   ${name} (${seconds}s) ${summary}`);
  }else{
    failed.push(name);
    console.log(`FAIL ${name} (${seconds}s)`);
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
  }
}
if(failed.length){
  console.error(`\n${failed.length} of ${suites.length} suites failed: ${failed.join(', ')}`);
  process.exit(1);
}
console.log(`\nAll ${suites.length} suites passed.`);
