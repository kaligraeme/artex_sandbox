const assert = require('node:assert/strict');
const e = require('../js/wire-engine.js');
const catalogue = require('../js/gang-techniques.js');
const gangs = ['lockbit','conti','blackcat','hive','revil'];
const modes = ['baseline','patch','soc','combined'];
const success = run => run.events.filter(event => event.outcome === 'succeeded');
const windows = run => success(run).filter(event => event.targetId.startsWith('windows-'));
const run = (estate, gang, mode = 'baseline') => e.simulateWireRun(estate, mode, gang);
assert.equal(catalogue.sources.attackVersion, '20.1');
assert.equal(e.gangTechniqueEvidence('conti','T1021.002').basis, 'threat_vision_attack_mapping');
assert.equal(e.gangTechniqueEvidence('revil','T1047').basis, 'threat_vision_attack_mapping');
assert.equal(e.gangTechniqueEvidence('hive','T1566.001').basis, 'affiliate_reporting');
assert.equal(e.gangTechniqueEvidence('hive','T1021.002'), null, 'No invented Hive-to-SMB mapping');
assert.equal(e.gangTechniqueEvidence('blackcat','T1566.001'), null, 'Do not infer phishing from a different affiliate');
assert.equal(e.gangTechniqueEvidence('lockbit','T1566.001').technique, 'T1566', 'Parent filter includes children');
assert.equal(e.gangTechniqueEvidence('revil','T1566.002'), null, 'Attachment evidence does not license a link');

const estate = e.generateEstate({seed:3,seedExercise:true});
const snapshot = JSON.stringify(estate);
const conti = run(estate,'conti');
const revil = run(estate,'revil');
assert(windows(conti).some(event => event.targetId === 'windows-records'));
assert(windows(conti).some(event => event.technique === 'T1021.002'));
assert(windows(revil).some(event => event.technique === 'T1047'));
assert(!windows(revil).some(event => event.technique === 'T1021.002'));
assert(windows(run(estate,'hive')).some(event => event.technique === 'T1566.001'));
assert(windows(run(estate,'hive')).some(event => event.technique === 'T1021.001'));
assert(windows(run(estate,'hive')).some(event => event.targetId === 'windows-records'));
assert(!windows(run(estate,'artex')).some(event => event.targetId === 'windows-desktop'));
assert(!windows(run(estate,'blackcat')).some(event => event.targetId === 'windows-desktop'));
assert(windows(run(estate,'conti','patch')).some(event => event.targetId === 'windows-records'), 'HTTP WAF does not block email/SMB');
assert(conti.events.some(event => event.policySkipped), 'Unsupported methods stay explicit');
assert(success(conti).every(event => event.attackerEvidence), 'Every chosen method has policy provenance');

for (const condition of ['userOpensAttachment','attachmentExecutionAllowed','mailFilterBlocksAttachment']) {
  const modified = structuredClone(estate);
  modified.assets.find(a => a.id === 'windows-desktop').conditions[condition] = condition === 'mailFilterBlocksAttachment';
  assert(!windows(run(modified,'conti')).some(event => event.targetId === 'windows-desktop'), condition);
}
for (const change of ['route','credential','permission','revoked','expired','audience','mfa']) {
  const modified = structuredClone(estate);
  const credential = modified.credentials.find(c => c.sourceAssetId === 'windows-desktop' && c.audience === 'windows-management');
  assert(credential);
  if (change === 'route') modified.relationships = modified.relationships.filter(r => r.sourceId !== 'windows-desktop');
  if (change === 'credential') modified.credentials = modified.credentials.filter(c => c !== credential);
  if (change === 'permission') credential.permissions = ['read'];
  if (change === 'revoked') credential.revoked = true;
  if (change === 'expired') credential.expired = true;
  if (change === 'audience') credential.audience = 'wrong-host';
  if (change === 'mfa') credential.mfaRequired = true;
  assert(!windows(run(modified,'conti')).some(event => event.targetId === 'windows-records'), change);
}
const remoteEstate = e.generateEstate({seed:8});
assert(windows(run(remoteEstate,'blackcat')).some(event => event.technique === 'T1133'));
for (const condition of ['remoteLoginEnabled','mfaEnforced']) {
  const modified = structuredClone(remoteEstate);
  modified.assets.find(a => a.id === 'windows-rdp').conditions[condition] = condition === 'mfaEnforced';
  assert(!windows(run(modified,'blackcat')).some(event => event.targetId === 'windows-rdp'), condition);
}
for (const missing of ['finding','mfa-condition']) {
  const modified = structuredClone(remoteEstate);
  if (missing === 'finding') modified.findings = modified.findings.filter(f => f.assetId !== 'windows-rdp');
  else delete modified.assets.find(a => a.id === 'windows-rdp').conditions.mfaEnforced;
  assert(!windows(run(modified,'blackcat')).some(event => event.targetId === 'windows-rdp'), missing);
}

for (let seed=1; seed<=30; seed++) {
  const scenario = e.generateEstate({seed,seedExercise:true});
  const before = JSON.stringify(scenario);
  for (const gang of [...gangs,'artex']) for (const mode of modes) {
    const result = run(scenario,gang,mode);
    assert.deepEqual(run(scenario,gang,mode),result,'Replay preserves policy, time and defense outcomes');
    if (gang === 'artex') assert(!success(result).some(event => event.finding?.requiresUserInteraction));
    else for (const event of success(result)) {
      if (['modeled_supporting_access','modeled_decoy_interaction'].includes(event.attackerEvidence?.basis)) assert(event.sourceId);
      else assert(e.gangTechniqueEvidence(gang,event.technique));
    }
    assert.equal(result.lanes,gang === 'artex' ? 3 : 1);
  }
  assert.equal(JSON.stringify(scenario),before,'Actor/defense switches cannot redraw estate');
}
assert.equal(JSON.stringify(estate),snapshot);
console.log('PASS gang policy: sourced filters, distinct SMB/WMI choices, phishing gates, RDP/MFA, credentials, reachability, WAF scope, 720 paired runs and replay');
